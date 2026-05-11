require 'fluent/plugin/output'
require 'openssl'
require 'socket'

module Fluent
  module Plugin
    class OutSyslogRFC5424 < Output
      Fluent::Plugin.register_output('syslog_rfc5424', self)

      helpers :socket, :formatter

      DEFAULT_FORMATTER = "syslog_rfc5424"

      class SyslogWriteTimeout < StandardError; end

      config_param :host, :string
      config_param :port, :integer

      config_param :transport, :string, default: "tls"

      # tls
      config_param :insecure, :bool, default: false
      config_param :trusted_ca_path, :string, default: nil

      # io timeout
      config_param :io_timeout, :integer, default: 5
      config_param :connect_timeout, :integer, default: 5

      # retry
      config_param :retry_limit, :integer, default: 3
      config_param :retry_interval, :float, default: 0.5
      config_param :exponential_backoff, :bool, default: true

      # reconnect
      config_param :reconnect_interval, :integer, default: 300

      # connection strategy: true=persistent (with reconnect), false=per-chunk
      config_param :persistent_connection, :bool, default: true

      # tcp keepalive
      config_param :keep_alive, :bool, default: true
      config_param :keep_alive_idle, :integer, default: 30
      config_param :keep_alive_cnt, :integer, default: 3
      config_param :keep_alive_intvl, :integer, default: 10

      config_section :format do
        config_set_default :@type, DEFAULT_FORMATTER
      end

      ##########################################################
      # lifecycle
      ##########################################################

      def configure(conf)
        super

        @formatter = formatter_create

        @socket = nil
        @socket_created_at = nil

        @mutex = Mutex.new

        @keep_alive_enabled = @keep_alive && %w[tcp tls].include?(@transport)

        if @keep_alive_enabled
          unless Socket.const_defined?(:SO_KEEPALIVE)
            log.warn("TCP keepalive is not supported on this platform")
            @keep_alive_enabled = false
          end
        end
      end

      def multi_workers_ready?
        true
      end

      def close
        super
        close_socket
      end

      # Connection semantics:
      #   persistent_connection=true  → one socket reused across chunks until reconnect_interval
      #   persistent_connection=false → new socket per chunk, closed in ensure
      def write(chunk)
        tag = chunk.metadata.tag

        begin
          chunk.each do |time, record|
            data = @formatter.format(tag, time, record)

            log.info(
              "syslog send",
              host: @host,
              port: @port,
              transport: @transport,
              bytes: data.bytesize,
              payload: data
            )

            send_msg(data)
          end
        ensure
          close_socket unless @persistent_connection
        end
      end

      private

      def send_msg(data)
        return send_udp(data) if @transport == 'udp'

        retry_count = 0
        retry_interval = @retry_interval.to_f
        payload = data.b

        begin
          @mutex.synchronize do
            # Reconnect if interval elapsed
            reconnect_socket if @persistent_connection && should_reconnect?
            # Ensure socket exists and is alive
            socket = socket_for_send
            # Write payload
            write_all_locked(socket, payload)
          end

        rescue => e
          if retry_count < @retry_limit
            log.warn(
              "syslog write failed, reconnect and retry",
              error: e.message,
              error_class: e.class,
              retry_count: retry_count + 1,
              host: @host,
              port: @port
            )

            close_socket

            sleep retry_interval

            retry_count += 1
            retry_interval *= 2 if @exponential_backoff

            retry
          end

          log.error(
            "syslog write failed after retries",
            error: e.message,
            error_class: e.class,
            host: @host,
            port: @port
          )

          close_socket

          raise
        end
      end

      # write_nonblock returns:
      #   nil  → EOF (remote closed), raise to trigger close+retry with full payload
      #   0    → ambiguous (TCP buffer full, TLS renegotiation, etc.), raise to retry
      #   >0   → bytes written, accumulate and continue
      def write_all_locked(socket, payload)
        total = 0
        length = payload.bytesize

        while total < length
          begin
            written = socket.write_nonblock(payload.byteslice(total..-1))

            if written.nil?
              # remote peer closed connection — raise to trigger retry with full payload
              raise SyslogWriteTimeout, "remote peer closed connection (wrote #{total}/#{length} bytes)"
            elsif written == 0
              # write_nonblock returned 0 without raising.
              # Ambiguous cause: TCP buffer full (needs writable) or TLS
              # renegotiation (needs readable). Since the correct wait direction
              # depends on the underlying transport, raise and let the outer
              # retry close+reconnect handle it cleanly.
              raise SyslogWriteTimeout, "write_nonblock returned 0 (wrote #{total}/#{length} bytes)"
            else
              total += written
            end

          rescue IO::WaitWritable,
                 OpenSSL::SSL::SSLErrorWaitWritable

            unless IO.select(nil, [socket], nil, @io_timeout)
              raise SyslogWriteTimeout, "syslog write timeout"
            end

            retry

          rescue IO::WaitReadable,
                 OpenSSL::SSL::SSLErrorWaitReadable

            unless IO.select([socket], nil, nil, @io_timeout)
              raise SyslogWriteTimeout, "syslog wait readable timeout"
            end

            retry
          end
        end
      end

      def send_udp(data)
        # UDP is connectionless; create ephemeral socket
        socket = socket_create(:udp, @host, @port, connect: true)
        begin
          socket.write(data)
        ensure
          socket.close
        end

      rescue => e
        log.warn(
          "syslog udp write failed",
          error: e.message,
          error_class: e.class
        )
        raise
      end

      def ensure_socket
        @mutex.synchronize do
          socket_for_send
        end
      end

      def socket_for_send
        return @socket if socket_alive?(@socket)

        close_socket_unlocked

        log.info(
          "creating syslog socket",
          host: @host,
          port: @port,
          transport: @transport
        )

        @socket = socket_create(
          @transport.to_sym,
          @host,
          @port,
          **socket_options
        )

        @socket_created_at = Fluent::Clock.now

        apply_keepalive

        @socket
      end

      def socket_options
        case @transport
        when 'udp'
          { connect: true }

        when 'tls'
          {
            connect_timeout: @connect_timeout,
            insecure: @insecure,
            verify_fqdn: !@insecure,
            cert_paths: @trusted_ca_path
          }

        else # tcp
          {
            connect_timeout: @connect_timeout
          }
        end
      end

      def should_reconnect?
        return false unless @socket
        return false unless @reconnect_interval > 0
        age = Fluent::Clock.now - @socket_created_at
        age >= @reconnect_interval
      end

      def reconnect_socket
        log.info(
          "reconnecting syslog socket",
          socket_age: Fluent::Clock.now - @socket_created_at,
          reconnect_interval: @reconnect_interval
        )
        close_socket_unlocked
      end

      def socket_alive?(socket)
        return false unless socket
        return false if socket.closed?

        # Check for socket errors using getsockopt
        begin
          socket.getsockopt(Socket::SOL_SOCKET, Socket::SO_ERROR).int == 0
        rescue => e
          false
        end
      end

      def apply_keepalive
        return unless @keep_alive_enabled

        raw_socket =
          if @transport == 'tls'
            @socket.io
          else
            @socket
          end

        # Enable SO_KEEPALIVE to detect dead connections
        raw_socket.setsockopt(
          Socket::SOL_SOCKET,
          Socket::SO_KEEPALIVE,
          1
        )

        # Set TCP_KEEPIDLE: time before first keepalive probe
        if Socket.const_defined?(:TCP_KEEPIDLE)
          raw_socket.setsockopt(
            Socket::IPPROTO_TCP,
            Socket::TCP_KEEPIDLE,
            @keep_alive_idle
          )
        end

        # Set TCP_KEEPCNT: number of keepalive probes
        if Socket.const_defined?(:TCP_KEEPCNT)
          raw_socket.setsockopt(
            Socket::IPPROTO_TCP,
            Socket::TCP_KEEPCNT,
            @keep_alive_cnt
          )
        end

        # Set TCP_KEEPINTVL: interval between keepalive probes
        if Socket.const_defined?(:TCP_KEEPINTVL)
          raw_socket.setsockopt(
            Socket::IPPROTO_TCP,
            Socket::TCP_KEEPINTVL,
            @keep_alive_intvl
          )
        end

        # Enable TCP_NODELAY to reduce latency
        if Socket.const_defined?(:TCP_NODELAY)
          raw_socket.setsockopt(
            Socket::IPPROTO_TCP,
            Socket::TCP_NODELAY,
            1
          )
        end

        log.info(
          "tcp keepalive enabled",
          idle: @keep_alive_idle,
          cnt: @keep_alive_cnt,
          intvl: @keep_alive_intvl,
          persistent_connection: @persistent_connection
        )

      rescue => e
        log.warn(
          "failed to apply TCP keepalive",
          error: e.message,
          error_class: e.class
        )
      end

      def close_socket
        socket = nil

        @mutex.synchronize do
          socket = @socket
          @socket = nil
          @socket_created_at = nil
        end

        return unless socket

        begin
          socket.close unless socket.closed?
        rescue => e
          log.warn(
            "socket close failed",
            error: e.message,
            error_class: e.class
          )
        end
      end

      def close_socket_unlocked
        socket = @socket
        @socket = nil
        @socket_created_at = nil

        return unless socket

        begin
          socket.close unless socket.closed?
        rescue => e
          log.warn(
            "socket close failed",
            error: e.message,
            error_class: e.class
          )
        end
      end
    end
  end
end
