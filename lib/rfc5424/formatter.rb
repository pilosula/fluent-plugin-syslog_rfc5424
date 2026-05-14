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
        
        # 统一使用 Time.at 处理所有时间戳
        # 这样可以避免 DateTime.strptime 对系统时区的依赖
        if timestamp.is_a?(Fluent::EventTime)
          ts_value = timestamp.to_r
        else
          # 转换为 Rational 以保持精度
          ts_value = timestamp.to_r
        end
        
        # 计算调整后的时间戳（加上时区偏移）
        adjusted_ts = ts_value + offset
        
        # 转为UTC时间对象
        time = Time.at(adjusted_ts).utc
        
        # 格式化输出
        time.strftime('%FT%T.%6N') + (timezone || '+00:00')
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