# encoding: utf-8
require "logstash/outputs/base"
require "logstash/namespace"
require "logstash/json"
require "uri"
require "logstash/plugin_mixins/http_client"
require "zlib"
require 'json'
require 'net/http'

class LogStash::Outputs::Bcdb < LogStash::Outputs::Base
  include LogStash::PluginMixins::HttpClient

  concurrency :shared

  attr_accessor :is_batch

  VALID_METHODS = ["put", "post", "patch", "delete", "get", "head"]

  RETRYABLE_MANTICORE_EXCEPTIONS = [
    ::Manticore::Timeout,
    ::Manticore::SocketException,
    ::Manticore::ClientProtocolException,
    ::Manticore::ResolutionFailure,
    ::Manticore::SocketTimeout
  ]

  # This output lets you send events to a
  # generic HTTP(S) endpoint
  #
  # This output will execute up to 'pool_max' requests in parallel for performance.
  # Consider this when tuning this plugin for performance.
  #
  # Additionally, note that when parallel execution is used strict ordering of events is not
  # guaranteed!
  #
  # Beware, this gem does not yet support codecs. Please use the 'format' option for now.

  config_name "bcdb"

  config :url, :validate => :string
  # BCDB data endpoint
  config :base_url, :validate => :string, :required => :true

  # BCDB Auth endpoint
  config :auth_url, :validate => :string, :required => :true

  # BCDB database entity model name
  config :bcdb_entity, :validate => :string, :default => "loglines"

  config :username,  :validate => :string, :required => :true
  config :password, :validate => :string, :required => :true
  config :client_id, :validate => :string, :required => :true
  config :client_secret, :validate => :string, :required => :true
  config :grant_type, :validate => ["password", "authorization_code"], :default => "password"

  # The HTTP Verb. One of "put", "post", "patch", "delete", "get", "head"
  config :http_method, :validate => VALID_METHODS, :default => "post"

  # Custom headers to use
  # format is `headers => ["X-My-Header", "%{host}"]`
  config :headers, :validate => :hash, :default => {}

  # Content type
  #
  # If not specified, this defaults to the following:
  #
  # * if format is "json", "application/json"
  # * if format is "form", "application/x-www-form-urlencoded"
  config :content_type, :validate => :string

  # Set this to false if you don't want this output to retry failed requests
  config :retry_failed, :validate => :boolean, :default => true

  # If encountered as response codes this plugin will retry these requests
  config :retryable_codes, :validate => :number, :list => true, :default => [429, 500, 502, 503, 504]

  # If you would like to consider some non-2xx codes to be successes
  # enumerate them here. Responses returning these codes will be considered successes
  config :ignorable_codes, :validate => :number, :list => true

  # This lets you choose the structure and parts of the event that are sent.
  #
  #
  # For example:
  # [source,ruby]
  #    mapping => {"foo" => "%{host}"
  #               "bar" => "%{type}"}
  config :mapping, :validate => :hash

  # Set the format of the http body.
  #
  # If form, then the body will be the mapping (or whole event) converted
  # into a query parameter string, e.g. `foo=bar&baz=fizz...`
  #
  # If message, then the body will be the result of formatting the event according to message
  #
  # Otherwise, the event is sent as json.
  config :format, :validate => ["json", "json_batch"], :default => "json"

  # Set this to true if you want to enable gzip compression for your http requests
  config :http_compression, :validate => :boolean, :default => false

  config :message, :validate => :string


  def bcdb_authorise()
      auth_uri = URI.parse(@auth_url)
      auth_data = {
          :username => @username,
          :password => @password,
          :client_id => @client_id,
          :client_secret => @client_secret,
          :grant_type => @grant_type
      }
      status = true
      begin
          unless (@token_oauth && (@expires_token && Time.now.utc < @expires_token))
              https= Net::HTTP.new(auth_uri.host,auth_uri.port)
              https.use_ssl = auth_uri.scheme == 'https'

              request = Net::HTTP::Post.new(auth_uri.path)
              request.set_form_data(auth_data)
              request['Content-Type'] = "application/x-www-form-urlencoded"
              resp = https.request(request)
              bcdb_response = {}
              bcdb_response = JSON.parse(resp.body) rescue bcdb_response["code"] = 5000.to_s
              if resp.code == 200.to_s && bcdb_response['access_token']
                  @token_oauth = bcdb_response['access_token']
                  @headers["Authorization"] = "Bearer #{@token_oauth}"
                  @expires_token = Time.now.utc + bcdb_response['expires_in'].to_i
              else
                  status = false
                  @logger.error("Authentification failed please check your credentials")
              end
          end
      rescue => e
        # This should never happen unless there's a flat out bug in the code
        @logger.error("Error Makeing Authorization Request to BCDB",
          :class => e.class.name,
          :message => e.message,
          :backtrace => e.backtrace)
        sleep(2)
        bcdb_authorise()
      end
      return status
  end

  def bcdb_update_schema(data, cached_keys=false)
      bcdb_authorise()
      schema_uri = URI.parse(@create_schema_url)
      schema_properties = {}
      data.each do |key|
          schema_properties["#{key}"] = {
              :"$id" => "/properties/#{schema_properties["#{key}"]}",
              :type => ["string", "object", "array"],
              :title => "The #{schema_properties["#{key}"]} Schema"
          }
      end
      schema_data = {
          :type => "object",
          :"$id" => "http://example.com/"+@bcdb_entity+".json",
          :"$schema" => "http://json-schema.org/draft-07/schema#",
          :title => "The Root Schema",
          :properties => schema_properties,
          :autoId => true
      }
      body = JSON(schema_data)

      if cached_keys
          request = bcdb_url(schema_uri,'put', body)
      else
          request = bcdb_url(schema_uri,'post',body)
          resp = JSON.parse(request.body)["code"] rescue  @logger.error("[BCDB SCHEMA] Unexpected error")
          if request.code == 403
              @logger.error("Authentification failed please check your credentials")
          elsif resp == 4009 || resp ==4000
              request = bcdb_url(schema_uri,'put', body)
          end
      end
     return data, true
  end
  def bcdb_url(uri,type,body)
      bcdb_request = Net::HTTP.new(uri.host,uri.port)
      bcdb_request.use_ssl = uri.scheme == 'https'
      case type
      when 'post'
          request = Net::HTTP::Post.new(uri.path)
      when 'put'
          request = Net::HTTP::Put.new(uri.path)
      end
      request.body = body
      request['Content-Type'] = "application/json"
      request['authorization'] = "Bearer #{@token_oauth}"
      response = bcdb_request.request(request)
      return response
  end

  def register
    @http_method = @http_method.to_sym

    # We count outstanding requests with this queue
    # This queue tracks the requests to create backpressure
    # When this queue is empty no new requests may be sent,
    # tokens must be added back by the client on success
    @request_tokens = SizedQueue.new(@pool_max)
    @pool_max.times {|t| @request_tokens << true }

    @requests = Array.new

    if @content_type.nil?
      case @format
        when "form" ; @content_type = "application/x-www-form-urlencoded"
        when "json" ; @content_type = "application/json"
        when "json_batch" ; @content_type = "application/json"
        when "message" ; @content_type = "text/plain"
      end
    end

    @is_batch = @format == "json_batch"

    @headers["Content-Type"] = @content_type

    validate_format!
    bcdb_authorise()
    @create_schema_url = "#{@base_url}" + "/data/catalog/_JsonSchema/" + "#{@bcdb_entity}"
    if  @format == "json_batch"
        @url = "#{@base_url}" + "/data/bulkAsync/" + "#{@bcdb_entity}"
    else
        @url = "#{@base_url}" + "/data/" + "#{@bcdb_entity}"
    end

    # Run named Timer as daemon thread
    @timer = java.util.Timer.new("HTTP Output #{self.params['id']}", true)
  end # def register

  def multi_receive(events)
    return if events.empty?
    send_events(events)
  end

  class RetryTimerTask < java.util.TimerTask
    def initialize(pending, event, attempt)
      @pending = pending
      @event = event
      @attempt = attempt
      super()
    end

    def run
      @pending << [@event, @attempt]
    end
  end

  def log_retryable_response(response)
    if (response.code == 429)
      @logger.debug? && @logger.debug("Encountered a 429 response, will retry. This is not serious, just flow control via HTTP")
    else
      @logger.warn("Encountered a retryable HTTP request in HTTP output, will retry", :code => response.code, :body => response.body)
    end
  end

  def log_error_response(response, url, event)
    log_failure(
              "Encountered non-2xx HTTP code #{response.code}",
              :response_code => response.code,
              :url => url,
              :event => event
            )
  end

  def send_events(events)
    successes = java.util.concurrent.atomic.AtomicInteger.new(0)
    failures  = java.util.concurrent.atomic.AtomicInteger.new(0)
    retries = java.util.concurrent.atomic.AtomicInteger.new(0)
    event_count = @is_batch ? 1 : events.size

    pending = Queue.new
    if @is_batch
      pending << [events, 0]
    else
      events.each {|e| pending << [e, 0]}
    end

    while popped = pending.pop
      break if popped == :done

      event, attempt = popped

      action, event, attempt = send_event(event, attempt)
      begin
        action = :failure if action == :retry && !@retry_failed

        case action
        when :success
          successes.incrementAndGet
        when :retry
          retries.incrementAndGet

          next_attempt = attempt+1
          sleep_for = sleep_for_attempt(next_attempt)
          @logger.info("Retrying http request, will sleep for #{sleep_for} seconds")
          timer_task = RetryTimerTask.new(pending, event, next_attempt)
          @timer.schedule(timer_task, sleep_for*1000)
        when :failure
          failures.incrementAndGet
        else
          raise "Unknown action #{action}"
        end

        if action == :success || action == :failure
          if successes.get+failures.get == event_count
            pending << :done
          end
        end
      rescue => e
        # This should never happen unless there's a flat out bug in the code
        @logger.error("Error sending HTTP Request",
          :class => e.class.name,
          :message => e.message,
          :backtrace => e.backtrace)
        failures.incrementAndGet
        raise e
      end
    end
  rescue => e
    @logger.error("Error in http output loop",
            :class => e.class.name,
            :message => e.message,
            :backtrace => e.backtrace)
    raise e
  end

  def sleep_for_attempt(attempt)
    sleep_for = attempt**2
    sleep_for = sleep_for <= 60 ? sleep_for : 60
    (sleep_for/2) + (rand(0..sleep_for)/2)
  end

  def send_event(event, attempt)
    bcdb_authorise()

    body = event_body(event)
    # Send the request
    url = @is_batch ? @url : event.sprintf(@url)
    headers = @is_batch ? @headers : event_headers(event)

    # Compress the body and add appropriate header
    if @http_compression == true
      headers["Content-Encoding"] = "gzip"
      body = gzip(body)
    end

    # Create an async request
    response = client.send(@http_method, url, :body => body, :headers => headers).call
    @logger.debug("[MAKEING REQUEST] Url: #{url}, response  #{response.inspect}")
    if !response_success?(response)
      if retryable_response?(response)
        log_retryable_response(response)
        return :retry, event, attempt
      else
        log_error_response(response, url, event)
        return :failure, event, attempt
      end
    else
      return :success, event, attempt
    end

  rescue => exception
    will_retry = retryable_exception?(exception)
    log_failure("Could not fetch URL",
                :url => url,
                :method => @http_method,
                :body => body,
                :headers => headers,
                :message => exception.message,
                :class => exception.class.name,
                :backtrace => exception.backtrace,
                :will_retry => will_retry
    )

    if will_retry
      return :retry, event, attempt
    else
      return :failure, event, attempt
    end
  end

  def close
    @timer.cancel
    client.close
  end

  private

  def response_success?(response)
    code = response.code
    return true if @ignorable_codes && @ignorable_codes.include?(code)
    return code >= 200 && code <= 299
  end

  def retryable_response?(response)
    @retryable_codes && @retryable_codes.include?(response.code)
  end

  def retryable_exception?(exception)
    RETRYABLE_MANTICORE_EXCEPTIONS.any? {|me| exception.is_a?(me) }
  end

  # This is split into a separate method mostly to help testing
  def log_failure(message, opts)
    @logger.error("[HTTP Output Failure] #{message}", opts)
  end

  # Format the HTTP body
  def event_body(event)
    bcdb_authorise()
    # TODO: Create an HTTP post data codec, use that here
    if @format == "json"
      bcdb_keys = event.to_hash
      {"headers": bcdb_keys.delete("headers")}
      unless @cached_keys && @keys.sort == bcdb_keys.keys.sort
         @keys, @cached_keys = bcdb_update_schema(bcdb_keys.keys, @cached_keys)
      end
       return LogStash::Json.dump(map_event(event))
    elsif @format == "message"
      event.sprintf(@message)
    elsif @format == "json_batch"
      event.map {|e|
                                            if e.is_a?(Hash)
                                                {"headers": e.delete("headers")}
                                                bcdb_keys = e
                                            elsif
                                                bcdb_keys = e.to_hash
                                                {"headers": bcdb_keys.delete("headers")}
                                            end
                                            unless @cached_keys && @keys.sort == bcdb_keys.keys.sort
                                                @keys, @cached_keys = bcdb_update_schema(bcdb_keys.keys, @cached_keys)
                                            end
                                            map_event(e)
                                            }
      # data = { :records => [event] }
      @logger.debug("[BATCH POST EVENTS] #{event.count}, DATA: #{LogStash::Json.dump({"records"=> event})}")
      return LogStash::Json.dump({"records"=> event})

    else
      encode(map_event(event))
    end
  end

  # gzip data
  def gzip(data)
    gz = StringIO.new
    gz.set_encoding("BINARY")
    z = Zlib::GzipWriter.new(gz)
    z.write(data)
    z.close
    gz.string
  end

  def convert_mapping(mapping, event)
    if mapping.is_a?(Hash)
      mapping.reduce({}) do |acc, kv|
        k, v = kv
        acc[k] = convert_mapping(v, event)
        acc
      end
    elsif mapping.is_a?(Array)
      mapping.map { |elem| convert_mapping(elem, event) }
    else
      event.sprintf(mapping)
    end
  end

  def map_event(event)
    if @mapping
      convert_mapping(@mapping, event)
    else
      event.to_hash
    end
  end

  def event_headers(event)
    custom_headers(event) || {}
  end

  def custom_headers(event)
    return nil unless @headers

    @headers.reduce({}) do |acc,kv|
      k,v = kv
      acc[k] = event.sprintf(v)
      acc
    end
  end

  #TODO Extract this to a codec
  def encode(hash)
    return hash.collect do |key, value|
      CGI.escape(key) + "=" + CGI.escape(value.to_s)
    end.join("&")
  end


  def validate_format!
    if @format == "message"
      if @message.nil?
        raise "message must be set if message format is used"
      end

      if @content_type.nil?
        raise "content_type must be set if message format is used"
      end

      unless @mapping.nil?
        @logger.warn "mapping is not supported and will be ignored if message format is used"
      end
    end
  end
end
