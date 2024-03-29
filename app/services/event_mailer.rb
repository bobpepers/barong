# frozen_string_literal: true

require 'bunny'
require 'ostruct'

class EventMailer
  def initialize(events, exchanges, keychain)
    @exchanges = exchanges
    @keychain = keychain
    @events = events

    Kernel.at_exit { unlisten }
  end

  def call
    listen
  end

  private

  def listen
    unlisten

    @bunny_session = Bunny::Session.new(rabbitmq_credentials).tap(&:start)
    @bunny_channel = @bunny_session.channel

    queue = @bunny_channel.queue('', auto_delete: true, durable: true)
    @events.each do |event|
      exchange = @bunny_channel.direct(@exchanges[event[:exchange].to_sym][:name])
      queue.bind(exchange, routing_key: event[:key])
    end

    Rails.logger.info { 'Listening for events.' }
    queue.subscribe(manual_ack: true, block: true, &method(:handle_message))
  end

  def unlisten
    if @bunny_session || @bunny_channel
      Rails.logger.info { 'No longer listening for events.' }
    end

    @bunny_channel&.work_pool&.kill
    @bunny_session&.stop
  ensure
    @bunny_channel = nil
    @bunny_session = nil
  end

  def algorithm_verification_options(signer)
    { algorithms: @keychain[signer][:algorithm] }
  end

  def jwt_public_key(signer)
    OpenSSL::PKey.read(Base64.urlsafe_decode64(@keychain[signer][:value]))
  end

  def rabbitmq_credentials
    if Barong::App.config.event_api_rabbitmq_url.present?
      Barong::App.config.event_api_rabbitmq_url
    else
      {
        host: Barong::App.config.event_api_rabbitmq_host,
        port: Barong::App.config.event_api_rabbitmq_port,
        username: Barong::App.config.event_api_rabbitmq_username,
        password: Barong::App.config.event_api_rabbitmq_password
      }
    end
  end

  def handle_message(delivery_info, _metadata, payload)
    retries ||= 0
    exchange    = @exchanges.select { |_, ex| ex[:name] == delivery_info[:exchange] }
    exchange_id = exchange.keys.first.to_s
    signer      = exchange[exchange_id.to_sym][:signer]

    result = verify_jwt(payload, signer.to_sym)

    raise "Failed to verify signature from #{signer}." \
      unless result[:verified].include?(signer.to_sym)

    config = @events.select do |event|
      event[:key] == delivery_info[:routing_key] &&
        event[:exchange] == exchange_id
    end.first

    event = result[:payload].fetch(:event)
    obj   = JSON.parse(event.to_json, object_class: OpenStruct)

    user  = User.includes(:profile).find_by(uid: obj.record.user.uid)
    language = user.language.to_sym

    #Rails.logger.warn { "obj #{obj}" }
    #language = obj.record.language.downcase.to_sym
    Rails.logger.warn { "Language #{language}" }

    unless config[:templates].key?(language)
      Rails.logger.error { "Language #{language} is not supported. Skipping." }
      Logger.new('/proc/1/fd/1').warn(language)
      return
    end

    params = {
      subject: config[:templates][language][:subject],
      template_name: config[:templates][language][:template_path],
      record: obj.record,
      changes: obj.changes,
      user: user
    }

    Rails.logger.warn ("JSON Response:  #{params} ")
    Logger.new('/proc/1/fd/1').warn("JSON Response:  #{params} ")

    Postmaster.process_payload(params).deliver_now
    @bunny_channel.acknowledge(delivery_info.delivery_tag, false)

  rescue StandardError => e
    Logger.new('/proc/1/fd/1').warn("Retry:  #{retries}")
    Rails.logger.error { e.inspect }
    Logger.new('/proc/1/fd/1').warn(e.inspect)
    sleep(2)
    retry if (retries += 1) < 10
  end

  def verify_jwt(payload, signer)
    options = algorithm_verification_options(signer)
    JWT::Multisig.verify_jwt JSON.parse(payload), { signer => jwt_public_key(signer) },
                             options.compact
  end

  class << self
    def call(*args)
      new(*args).call
    end
  end
end