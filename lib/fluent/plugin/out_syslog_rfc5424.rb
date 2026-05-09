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

      ##########################################################
      # config
      ##########################################################

      config_param :host, :string
      config_param :port, :integer

      config_param :transport, :string, default: "tls"

      # tls
      config_param :insecure, :bool, default: false
      config_param :trusted_ca_path, :string, default: nil

      # io timeout
      config_param :io_timeout, :integer, default: 5
      config_param :socket_poll_timeout, :float, default: 0.1

      # retry
      config_param :retry_limit, :integer, default: 3
      config_param :retry_interval, :float, default: 0.5
      config_param :exponential_backoff, :bool, default: true

      # reconnect
      config_param :reconnect_interval, :integer, default: 300

      # connection strategy: true=persistent (with reconnect), false=per-chunk
      config_param :persistent_connection, :bool, default: false

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

      ##########################################################
      # write
      ##########################################################

      def write(chunk)
        tag = chunk.metadata.tag

        begin
          chunk.each do |time, record|
            data = @formatter.format(tag, time, record)

            log.debug(
              "syslog send",
              host: @host,
              port: @port,
              transport: @transport,
              bytes: data.bytesize
            )

            send_msg(data)
          end
        ensure
          # Close connection after each chunk to prevent half-open connection issues
          # unless persistent_connection is explicitly enabled
          close_socket unless @persistent_connection
        end
      end

      ##########################################################
      # send
      ##########################################################

      private

      def send_msg(data)
        return send_udp(data) if @transport == 'udp'

        retry_count = 0
        retry_interval = @retry_interval.to_f

        payload = data.b

        begin
          socket = @mutex.synchronize do
            reconnect_if_needed
            ensure_socket
          end

          # Poll socket before writing to detect half-open connections
          verify_socket_ready(socket)

          write_all(socket, payload)

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

      def write_all(socket, payload)
        total = 0

        while total < payload.bytesize
          begin
            written = socket.write_nonblock(payload.byteslice(total..-1))

            if written.nil? || written <= 0
              raise IOError, "socket write returned invalid length"
            end

            total += written

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

      ##########################################################
      # udp
      ##########################################################

      def send_udp(data)
        socket = ensure_socket
        socket.write(data)

      rescue => e
        log.warn(
          "syslog udp write failed",
          error: e.message,
          error_class: e.class
        )

        close_socket

        raise
      end

      ##########################################################
      # socket
      ##########################################################

      def ensure_socket
        return @socket if socket_alive?(@socket)

        close_socket

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
          {
            connect: true
          }

        when 'tls'
          {
            insecure: @insecure,
            verify_fqdn: !@insecure,
            cert_paths: @trusted_ca_path
          }

        else
          {}
        end
      end

      ##########################################################
      # reconnect
      ##########################################################

      def reconnect_if_needed
        return unless @socket
        return unless @reconnect_interval > 0

        age = Fluent::Clock.now - @socket_created_at

        if age >= @reconnect_interval
          log.info(
            "reconnecting syslog socket",
            socket_age: age,
            reconnect_interval: @reconnect_interval
          )

          close_socket
        end
      end

      ##########################################################
      # socket health
      ##########################################################

      def socket_alive?(socket)
        return false unless socket
        return false if socket.closed?

        raw_socket =
          if @transport == 'tls'
            socket.io
          else
            socket
          end

        so_error = raw_socket.getsockopt(
          Socket::SOL_SOCKET,
          Socket::SO_ERROR
        ).int

        so_error == 0

      rescue
        false
      end

      def verify_socket_ready(socket)
        return unless socket
        return if @transport == 'udp'

        raw_socket =
          if @transport == 'tls'
            socket.io
          else
            socket
          end

        # Poll socket for writability before sending
        # This detects half-open connections that appear connected but can't write
        ready = IO.select(nil, [socket], nil, @socket_poll_timeout)

        unless ready
          raise IOError, "socket not ready for writing (possible half-open connection)"
        end

      rescue => e
        log.warn(
          "socket readiness check failed",
          error: e.message,
          error_class: e.class
        )
        raise
      end

      ##########################################################
      # keepalive
      ##########################################################

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

      ##########################################################
      # close
      ##########################################################

      def close_socket
        @mutex.synchronize do
          return unless @socket

          begin
            @socket.close unless @socket.closed?

          rescue => e
            log.warn(
              "socket close failed",
              error: e.message,
              error_class: e.class
            )

          ensure
            @socket = nil
            @socket_created_at = nil
          end
        end
      end
    end
  end
end