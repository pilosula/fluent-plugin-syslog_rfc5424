require "test_helper"
require "fluent/plugin/out_syslog_rfc5424"

class OutSyslogRFC5424Test < Test::Unit::TestCase
  def setup
    Fluent::Test.setup
    @time = Fluent::EventTime.new(0, 123456)
    @formatted_log = "51 <14>1 1970-01-01T00:00:00.000123+00:00 - - - - - hi"
    @formatted_log_bytesize = @formatted_log.bytesize
  end

  def create_driver(conf = CONFIG)
    Fluent::Test::Driver::Output.new(Fluent::Plugin::OutSyslogRFC5424).configure(conf)
  end

  def create_socket
    socket = Object.new
    stub(socket).closed? { false }
    socket
  end

  def test_configure
    output_driver = create_driver %(
      @type syslog_rfc5424
      host example.com
      port 123
    )

    assert_equal "example.com", output_driver.instance.instance_variable_get(:@host)
    assert_equal 123, output_driver.instance.instance_variable_get(:@port)
  end

  def test_sends_a_message
    output_driver = create_driver %(
      @type syslog_rfc5424
      host example.com
      port 123
    )

    socket = create_socket
    mock(socket).write_nonblock(@formatted_log) { @formatted_log_bytesize }
    stub(socket).close

    any_instance_of(Fluent::Plugin::OutSyslogRFC5424) do |fluent_plugin|
      mock(fluent_plugin).socket_create(:tls, "example.com", 123, {:insecure=>false, :verify_fqdn=>true, :cert_paths=>nil}).returns(socket)
    end

    output_driver.run do
      output_driver.feed("tag", @time, {"log" => "hi"})
    end
  end

  def test_reconnects
    output_driver = create_driver %(
      @type syslog_rfc5424
      host example.com
      port 123
      retry_interval 0
    )

    bad_socket = create_socket
    mock(bad_socket).write_nonblock(@formatted_log) { raise Errno::EPIPE }
    stub(bad_socket).close

    good_socket = create_socket
    mock(good_socket).write_nonblock(@formatted_log) { @formatted_log_bytesize }
    stub(good_socket).close

    any_instance_of(Fluent::Plugin::OutSyslogRFC5424) do |fluent_plugin|
      mock(fluent_plugin).socket_create(:tls, "example.com", 123, {:insecure=>false, :verify_fqdn=>true, :cert_paths=>nil}).returns(bad_socket)
      mock(fluent_plugin).socket_create(:tls, "example.com", 123, {:insecure=>false, :verify_fqdn=>true, :cert_paths=>nil}).returns(good_socket)
    end

    output_driver.run do
      output_driver.feed("tag", @time, {"log" => "hi"})
    end
  end

  def test_persistent_connection_reuses_socket_within_chunk
    output_driver = create_driver %(
      @type syslog_rfc5424
      host example.com
      port 123
      persistent_connection true
    )

    socket = create_socket
    mock(socket).write_nonblock(@formatted_log) { @formatted_log_bytesize }
    mock(socket).write_nonblock(@formatted_log) { @formatted_log_bytesize }
    stub(socket).close

    any_instance_of(Fluent::Plugin::OutSyslogRFC5424) do |fluent_plugin|
      # Only one socket creation for both messages in same chunk
      mock(fluent_plugin).socket_create(:tls, "example.com", 123, {:insecure=>false, :verify_fqdn=>true, :cert_paths=>nil}).returns(socket).times(1)
    end

    output_driver.run do
      output_driver.feed("tag", @time, {"log" => "hi"})
      output_driver.feed("tag", @time, {"log" => "hi"})
    end
  end

  def test_persistent_connection_reconnects_after_interval
    output_driver = create_driver %(
      @type syslog_rfc5424
      host example.com
      port 123
      persistent_connection true
      reconnect_interval 0
    )

    first_socket = create_socket
    mock(first_socket).write_nonblock(@formatted_log) { @formatted_log_bytesize }
    stub(first_socket).close

    second_socket = create_socket
    mock(second_socket).write_nonblock(@formatted_log) { @formatted_log_bytesize }
    stub(second_socket).close

    any_instance_of(Fluent::Plugin::OutSyslogRFC5424) do |fluent_plugin|
      mock(fluent_plugin).socket_create(:tls, "example.com", 123, {:insecure=>false, :verify_fqdn=>true, :cert_paths=>nil}).returns(first_socket)
      mock(fluent_plugin).socket_create(:tls, "example.com", 123, {:insecure=>false, :verify_fqdn=>true, :cert_paths=>nil}).returns(second_socket)
    end

    output_driver.run do
      output_driver.feed("tag", @time, {"log" => "hi"})
      output_driver.feed("tag", @time, {"log" => "hi"})
    end
  end

  def test_non_tls
    output_driver = create_driver %(
      @type syslog_rfc5424
      host example.com
      port 123
      transport tcp
    )

    socket = create_socket
    mock(socket).write_nonblock(@formatted_log) { @formatted_log_bytesize }
    stub(socket).close

    any_instance_of(Fluent::Plugin::OutSyslogRFC5424) do |fluent_plugin|
      mock(fluent_plugin).socket_create(:tcp, "example.com", 123, {}).returns(socket)
    end

    output_driver.run do
      output_driver.feed("tag", @time, {"log" => "hi"})
    end
  end

  def test_insecure_tls
    output_driver = create_driver %(
      @type syslog_rfc5424
      host example.com
      port 123
      transport tls
      insecure true
    )

    socket = create_socket
    mock(socket).write_nonblock(@formatted_log) { @formatted_log_bytesize }
    stub(socket).close

    any_instance_of(Fluent::Plugin::OutSyslogRFC5424) do |fluent_plugin|
      mock(fluent_plugin).socket_create(:tls, "example.com", 123, {:insecure=>true, :verify_fqdn=>false, :cert_paths=>nil}).returns(socket)
    end

    output_driver.run do
      output_driver.feed("tag", @time, {"log" => "hi"})
    end
  end

  def test_secure_tls
    output_driver = create_driver %(
      @type syslog_rfc5424
      host example.com
      port 123
      transport tls
      trusted_ca_path supertrustworthy
    )

    socket = create_socket
    mock(socket).write_nonblock(@formatted_log) { @formatted_log_bytesize }
    stub(socket).close

    any_instance_of(Fluent::Plugin::OutSyslogRFC5424) do |fluent_plugin|
      mock(fluent_plugin).socket_create(:tls, "example.com", 123, {:insecure=>false, :verify_fqdn=>true, :cert_paths=>"supertrustworthy"}).returns(socket)
    end

    output_driver.run do
      output_driver.feed("tag", @time, {"log" => "hi"})
    end
  end

  def test_close_is_called_on_sockets
    output_driver = create_driver %(
      @type syslog_rfc5424
      host example.com
      port 123
      persistent_connection false
    )

    socket = create_socket
    stub(socket).write_nonblock(@formatted_log) { @formatted_log_bytesize }
    mock(socket).close

    any_instance_of(Fluent::Plugin::OutSyslogRFC5424) do |fluent_plugin|
      mock(fluent_plugin).socket_create(:tls, "example.com", 123, {:insecure=>false, :verify_fqdn=>true, :cert_paths=>nil}).returns(socket)
    end

    output_driver.run do
      output_driver.feed("tag", @time, {"log" => "hi"})
    end
  end

end
