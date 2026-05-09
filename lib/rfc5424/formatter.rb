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
        timezone: nil
      )
        Format % [priority, format_time(timestamp, timezone), hostname[0..254], app_name[0..47], proc_id[0..127], msg_id[0..31], sd, log]
      end

      def format_time(timestamp, timezone = nil)
        return "-" if timestamp.nil?
        offset = parse_timezone(timezone)
        if timestamp.is_a?(Fluent::EventTime)
          time = Time.at(timestamp.to_r + offset).utc
          time.strftime('%FT%T.%6N') + (timezone || '+00:00')
        else
          dt = DateTime.strptime(timestamp.to_s, '%s')
          time = dt.to_time + offset
          time.utc.strftime('%FT%T.%6N') + (timezone || '+00:00')
        end
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