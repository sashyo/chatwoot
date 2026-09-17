# frozen_string_literal: true

# minidauth field sealing client for Chatwoot.
#
# Talks to the language-agnostic minidauth-seal sidecar, which fronts minidauth and the Tide ORK
# cohort. Sealing turns a plaintext value into "ms1:<ciphertext>"; opening reverses it, but only for a
# reader the sidecar can verify AND whom minidauth's quorum granted the reading role. This app and its
# Postgres only ever hold ciphertext; the vendor key lives as threshold shares across the cohort and is
# never assembled here.
#
# Off unless MINIDAUTH_SEAL_URL is set. The reader token is a short-lived EdDSA JWT signed with a key
# only this app holds (MINIDAUTH_SEAL_SIGNING_KEY_FILE); minidauth verifies it with the public half, so
# there is no shared secret to leak.
require 'openssl'
require 'base64'
require 'json'
require 'net/http'
require 'uri'

module Minidauth
  module Sidecar
    MARKER = 'ms1:'

    module_function

    def enabled?
      ENV['MINIDAUTH_SEAL_URL'].to_s != ''
    end

    def sealed?(value)
      value.is_a?(String) && value.start_with?(MARKER)
    end

    def b64url(bytes)
      Base64.urlsafe_encode64(bytes, padding: false)
    end

    # Mint a short-lived assertion that this already-authenticated agent is the reader. Chatwoot has
    # verified the user (the id comes from the session, never the client); this token just carries that
    # identity to the sidecar, which re-verifies the signature and decrypts as this uid, gated by the
    # quorum grant. Short-lived so a captured token is useless within moments.
    def reader_token(uid)
      now = Time.now.to_i
      header = b64url(JSON.generate(alg: 'EdDSA', typ: 'JWT'))
      payload = b64url(JSON.generate(sub: uid.to_s, iat: now, exp: now + 15))
      key = signing_key
      raise 'Set MINIDAUTH_SEAL_SIGNING_KEY_FILE' unless key

      sig = b64url(key.sign(nil, "#{header}.#{payload}")) # Ed25519 sign (nil digest), OpenSSL 3
      "#{header}.#{payload}.#{sig}"
    end

    def signing_key
      @signing_key ||= begin
        file = ENV['MINIDAUTH_SEAL_SIGNING_KEY_FILE']
        pem = file ? File.read(file) : ENV['MINIDAUTH_SEAL_SIGNING_KEY']
        pem ? OpenSSL::PKey.read(pem) : nil
      end
    end

    # Seal a list of plaintext strings, returning the ms1: values in the same order. Fails closed: a
    # sidecar error raises so a write never silently stores plaintext.
    def seal(values)
      return values if values.empty?

      fields = {}
      values.each_with_index { |v, i| fields[i.to_s] = v }
      out = post('/seal', { fields: fields })
      values.each_index.map { |i| out.fetch('sealed').fetch(i.to_s) }
    end

    # Open a list of ms1: values as the reader named by reader_token, returning plaintext in order.
    # Best effort: any failure (no reader, ungranted, sidecar down) returns the values unchanged
    # (still sealed), so a read never crashes and ciphertext is the safe default.
    def open(values, reader_token)
      return values if values.empty? || reader_token.nil?

      fields = {}
      values.each_with_index { |v, i| fields[i.to_s] = v.delete_prefix(MARKER) }
      out = post('/open', { fields: fields }, reader_token)
      values.each_index.map { |i| out.fetch('fields').fetch(i.to_s) }
    rescue StandardError => e
      Rails.logger.warn("[minidauth-seal] leaving records sealed: #{e.message}") if defined?(Rails)
      values
    end

    def post(path, body, bearer = nil)
      uri = URI.join(ENV['MINIDAUTH_SEAL_URL'], path)
      req = Net::HTTP::Post.new(uri)
      req['Content-Type'] = 'application/json'
      req['Authorization'] = "Bearer #{bearer}" if bearer
      req.body = JSON.generate(body)
      res = Net::HTTP.start(uri.host, uri.port, open_timeout: 5, read_timeout: 15) { |http| http.request(req) }
      raise "minidauth-seal #{path} -> #{res.code} #{res.body}" unless res.code.to_i.between?(200, 299)

      res.body.to_s.empty? ? {} : JSON.parse(res.body)
    end
  end
end
