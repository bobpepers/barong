# frozen_string_literal: true


# 1/ check if ENV key exist then validate and set
# 2/ if no check in credentials then validate and set
# 3/ if no generate display warning, raise error in production, and set

require 'barong/app'
require 'barong/keystore'

begin
  private_key_path = ENV['JWT_PRIVATE_KEY_PATH']

  if !private_key_path.nil?
    pkey = Barong::KeyStore.open!(private_key_path)
    Rails.logger.info('Loading private key from: ' + private_key_path)

  elsif Rails.application.credentials.has?(:private_key)
    pkey = Barong::KeyStore.read!(Rails.application.credentials.private_key)
    Rails.logger.info('Loading private key from credentials.yml.enc')

  elsif !Rails.env.production?
    pkey = Barong::KeyStore.generate
    Rails.logger.warn('Warning !! Generating private key')

  else
    raise Barong::KeyStore::Fatal
  end
rescue Barong::KeyStore::Fatal
  Rails.logger.fatal('Private key is invalid')
  raise 'FATAL: Private key is invalid'
end

kstore = Barong::KeyStore.new(pkey)

Barong::App.define do |config|
  # General configuration
  # https://github.com/openware/barong/blob/master/docs/configuration.md#general-configuration
  config.set(:app_name, 'Barong')
  config.set(:barong_domain, 'barong.io')
  config.set(:barong_uid_prefix, 'ID', regex: /^[A-z]{2,6}$/)
  config.set(:barong_config, 'config/barong.yml', type: :path)
  config.set(:barong_maxminddb_path, '', type: :path)
  config.set(:session_expire_time, '1800', type: :integer)
  config.set(:barong_geoip_lang, 'en', values: %w[en de es fr ja ru])
  config.set(:barong_session_name, '_barong_session')
  config.set(:redis_url, 'redis://localhost:6379/1')
  config.set(:barong_captcha, 'recaptcha', values: %w[none recaptcha geetest])

  # Password configuration
  # https://github.com/openware/barong/blob/master/docs/configuration.md#password-configuration
  config.set(:password_regexp, '^(?=.*[[:lower:]])(?=.*[[:upper:]])(?=.*[[:digit:]])(?=.*[[:graph:]]).{8,80}$', type: :regexp)
  config.set(:password_min_entropy, '14', type: :integer)
  config.set(:password_use_dictionary, 'true', type: :bool)

  # Dependencies configuration (vault, redis, rabbitmq) ---------------
  # https://github.com/openware/barong/blob/master/docs/configuration.md#dependencies-configuration-vault-redis-rabbitmq
  config.set(:event_api_rabbitmq_host, 'localhost')
  config.set(:event_api_rabbitmq_port, '5672')
  config.set(:event_api_rabbitmq_username, 'guest')
  config.set(:event_api_rabbitmq_password, 'guest')
  config.set(:vault_address, 'http://localhost:8200')
  config.set(:vault_token, 'changeme')
  config.set(:redis_url, 'redis://localhost:6379/1')

  # SMTP configuration ------------------------------------------------
  # https://github.com/openware/barong/blob/master/docs/general/env_configuration.md#smtp-configuration
  config.set(:sender_email, 'noreply@barong.io')
  config.set(:sender_name, 'Barong')
  config.set(:smtp_password, '')
  config.set(:smtp_port, 1025)
  config.set(:smtp_host, 'localhost')
  config.set(:smtp_user, '')
  config.set(:default_language, 'en')
end

ActionMailer::Base.smtp_settings = {
  address: Barong::App.config.smtp_host,
  port: Barong::App.config.smtp_port,
  user_name: Barong::App.config.smtp_user,
  password: Barong::App.config.smtp_password
}

Barong::GeoIP.lang = Barong::App.config.barong_geoip_lang

Rails.application.config.x.keystore = kstore
Barong::App.config.keystore = kstore
