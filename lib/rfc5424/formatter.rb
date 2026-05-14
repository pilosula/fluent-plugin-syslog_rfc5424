require 'date'

module RFC5424
  class Formatter
    Format = "<%d>1 %s %s %s %s %s %s %s"

    class << self
      def parse_timezone(tz_str)
        return 0 unless tz_str
        if tz_str =~ /^([+-])(\d{2}):(\d{2})$/
          sign = $1 == '+' ? 1 : -1
          hours = $2.to_i
          minutes = $3.to_i
          sign * (hours * 3600 + minutes * 60)
        else
          0
        end
      end

      def format(
        priority: 14,
        timestamp: nil,
        log: "",
        hostname: "-",
        app_name: "-",
        proc_id: "-",
        msg_id: "-",
        sd: "-",
        timezone_offset: 0
      )
        Format % [priority, format_time(timestamp, timezone_offset), truncate(hostname, 255), truncate(app_name, 48), truncate(proc_id, 128), truncate(msg_id, 32), sd, log]
      end

      def format_time(timestamp, offset = 0)
        return "-" if timestamp.nil?

        time = Time.at(timestamp.to_r).utc.getlocal(offset)
        time.strftime('%FT%T.%6N%:z')
      end

      private

      def truncate(str, max)
        str.length > max ? str[0...max] : str
      end
    end
  end

  class StructuredData
    attr_reader :sd_id, :sd_elements

    def initialize(sd_id:, sd_elements: {})
      @sd_id = sd_id
      @sd_elements = sd_elements
    end

    def to_s
      el = @sd_elements.inject("") do |elements, tuple|
        elements + %{ #{tuple.first}="#{tuple.last}"}
      end
      %{[#{sd_id}#{el}]}
    end
  end
end
