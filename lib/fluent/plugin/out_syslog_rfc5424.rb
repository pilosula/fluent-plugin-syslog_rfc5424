require 'fluent/plugin/output'
require 'openssl'

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

      # retry
      config_param :retry_limit, :integer, default: 3
      config_param :retry_interval, :float, default: 0.5
      config_param :exponential_backoff, :bool, default: false

      # tcp keepalive
      config_param :keep_alive, :bool, default: false
      config_param :keep_alive_idle, :integer, default: nil
      config_param :keep_alive_cnt, :integer, default: nil
      config_param :keep_alive_intvl, :integer, default: nil

      config_section :format do
        config_set_default :@type, DEFAULT_FORMATTER
      end

      def configure(conf)
        super

        @formatter = formatter_create
        @socket = nil
        @mutex = Mutex.new

        @keep_alive_enabled = @keep_alive && %w[tcp tls].include?(@transport)
        if @keep_alive_enabled
          unless [:SOL_SOCKET, :SO_KEEPALIVE, :IPPROTO_TCP, :TCP_KEEPIDLE].all? { |c| Socket.const_defined?(c) }
            log.warn("TCP keepalive is not supported on this platform")
            @keep_alive_enabled = false
          end
        end
      end

      def multi_workers_ready?
        true
      end

      def write(chunk)
        tag = chunk.metadata.tag

        chunk.each do |time, record|
          data = @formatter.format(tag, time, record)

          log.debug(
            "syslog send",
            host: @host,
            port: @port,
            transport: @transport,
            bytes: data.bytesize,
            payload: data
          )

          send_msg(data)
        end
      end

      def close
        super
        close_socket
      end

      private

      ##########################################################
      # message send with retry
      ##########################################################

      def send_msg(data)
        return send_udp(data) if @transport == 'udp'

        payload = data.b
        payload_size = payload.bytesize
        retry_count = 0
        retry_interval = @retry_interval.to_f

        until payload_size <= 0
          begin
            result = @mutex.synchronize do
              socket = ensure_socket
              socket.write_nonblock(payload)
            end

            if result <= 0
              socket = ensure_socket
              IO.select(nil, [socket], nil, @io_timeout) if socket
              retry
            end

            payload_size -= result
            payload.slice!(0, result) if payload_size > 0

          rescue IO::WaitReadable,
                 OpenSSL::SSL::SSLErrorWaitReadable

            socket = ensure_socket
            unless IO.select([socket], nil, nil, @io_timeout)
              raise SyslogWriteTimeout, "syslog TLS wait timeout"
            end
            retry

          rescue IO::WaitWritable,
                 OpenSSL::SSL::SSLErrorWaitWritable

            socket = ensure_socket
            unless IO.select(nil, [socket], nil, @io_timeout)
              raise SyslogWriteTimeout, "syslog write timeout"
            end
            retry

          rescue => e
            if retry_count < @retry_limit
              log.info(
                "syslog write failed, reconnecting and retrying",
                error: e.message,
                error_class: e.class,
                host: @host,
                port: @port,
                transport: @transport,
                retry_attempt: retry_count + 1
              )

              sleep retry_interval
              retry_count += 1
              retry_interval *= 2 if @exponential_backoff
              close_socket
              retry
            else
              log.warn(
                "syslog write failed after all retries",
                error: e.message,
                error_class: e.class,
                host: @host,
                port: @port,
                transport: @transport
              )
              close_socket
              raise
            end
          end
        end
      end

      def send_udp(data)
        socket = ensure_socket
        socket.write(data)
      rescue => e
        log.warn(
          "syslog udp write failed",
          error: e.message,
          error_class: e.class,
          host: @host,
          port: @port
        )
        raise
      end

      ##########################################################
      # socket
      ##########################################################

      def ensure_socket
        return @socket if @socket

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
          socket_options
        )

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

      def apply_keepalive
        return unless @keep_alive_enabled

        tcp_socket = @socket
        tcp_socket = tcp_socket.io if @transport == 'tls'

        tcp_socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_KEEPALIVE, true)
        tcp_socket.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_KEEPIDLE, @keep_alive_idle) if @keep_alive_idle
        tcp_socket.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_KEEPCNT, @keep_alive_cnt) if @keep_alive_cnt && Socket.const_defined?(:TCP_KEEPCNT)
        tcp_socket.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_KEEPINTVL, @keep_alive_intvl) if @keep_alive_intvl && Socket.const_defined?(:TCP_KEEPINTVL)
      rescue => e
        log.warn(
          "failed to apply TCP keepalive",
          error: e.message,
          error_class: e.class
        )
      end

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
          end
        end
      end
    end
  end
end
