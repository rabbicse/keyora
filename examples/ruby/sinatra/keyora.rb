# frozen_string_literal: true

# Everything that talks to Keyora: configuration, the REST client and token verification.
require "json"
require "jwt"
require "logger"
require "net/http"
require "uri"

module Keyora
  URL = ENV.fetch("KEYORA_URL", "http://localhost:8080").chomp("/")
  # The `iss` tokens must carry. Differs from URL when Keyora is reached on an
  # internal address, for example from inside a container.
  ISSUER = ENV["KEYORA_ISSUER"].to_s.empty? ? URL : ENV["KEYORA_ISSUER"]
  CLIENT_ID = ENV["KEYORA_CLIENT_ID"].to_s
  CLIENT_SECRET = ENV["KEYORA_CLIENT_SECRET"].to_s

  if CLIENT_ID.empty? || CLIENT_SECRET.empty?
    abort "KEYORA_CLIENT_ID and KEYORA_CLIENT_SECRET are required (run examples/setup.sh)"
  end

  LOG = Logger.new($stderr, progname: "keyora")

  # Keyora could not be reached or gave an unusable answer.
  class Unavailable < StandardError; end
  # The token is genuine but past its `exp`. The client should refresh and retry.
  class TokenExpired < StandardError; end
  # The token failed any other check, or the signing keys could not be fetched.
  class TokenInvalid < StandardError; end

  NETWORK_ERRORS = [SystemCallError, SocketError, IOError, Timeout::Error,
                    Net::ProtocolError, OpenSSL::SSL::SSLError, JSON::ParserError].freeze

  module_function

  # --- REST calls (server side only: they carry the client secret) -----------

  # POST a JSON body to Keyora. Returns the status and the `{data|error, meta}` envelope.
  #
  # HTTP Basic with client_id:client_secret identifies this application to Keyora.
  # Raises Unavailable when Keyora cannot be reached or does not answer with its
  # JSON envelope; app.rb turns that into a 502.
  def post(path, body)
    req = Net::HTTP::Post.new(path, "Content-Type" => "application/json", "Accept" => "application/json")
    req.basic_auth(CLIENT_ID, CLIENT_SECRET)
    req.body = JSON.generate(body)
    res = request(req, read_timeout: 10)
    return [res.code.to_i, {}] if res.body.to_s.empty? # 204 No Content (logout)

    envelope = JSON.parse(res.body)
    raise Unavailable, "unexpected response from keyora" unless envelope.is_a?(Hash)

    [res.code.to_i, envelope]
  rescue *NETWORK_ERRORS => e
    raise Unavailable, "#{e.class}: #{e.message}"
  end

  # Ask Keyora for the live state of an access token.
  def introspect(token)
    status, envelope = post("/api/v1/auth/introspect", { "token" => token })
    unless status == 200 && envelope["data"].is_a?(Hash)
      raise Unavailable, "introspection failed with status #{status}"
    end

    envelope["data"]
  end

  def request(req, read_timeout:)
    uri = URI(URL)
    Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https",
                                        open_timeout: 5, read_timeout: read_timeout) do |http|
      http.request(req)
    end
  end

  # --- Signing keys -----------------------------------------------------------

  # Keyora's public keys, fetched on first use and cached for five minutes.
  # A token naming a key ID that is not cached triggers a re-fetch, so a key
  # rotation on the Keyora side needs no restart here. Re-fetches are spaced at
  # least ten seconds apart: the `kid` is attacker-controlled, and without the
  # limit every request with a made-up `kid` would cost a call to Keyora.
  module Jwks
    TTL = 300
    MIN_REFETCH_INTERVAL = 10

    @lock = Mutex.new
    @keys = []
    @fetched_at = nil

    # The loader ruby-jwt calls: first plainly, then, when no key matches the
    # token's `kid`, once more with `kid_not_found: true`.
    def self.call(options = {})
      @lock.synchronize do
        age = @fetched_at && (now - @fetched_at)
        stale = age.nil? || age > TTL
        unknown_kid = options[:kid_not_found] && age && age > MIN_REFETCH_INTERVAL
        refresh if stale || unknown_kid
        { keys: @keys }
      end
    end

    def self.refresh
      res = Keyora.request(Net::HTTP::Get.new("/.well-known/jwks.json"), read_timeout: 5)
      raise Unavailable, "JWKS request answered #{res.code}" unless res.code == "200"

      keys = JSON.parse(res.body).fetch("keys")
      # Only RSA signing keys are of interest: the algorithm is pinned to RS256.
      @keys = keys.select { |k| k["kty"] == "RSA" && k.fetch("use", "sig") == "sig" }
      @fetched_at = now
    rescue Unavailable, KeyError, *NETWORK_ERRORS => e
      # Keep serving the keys already cached, if any: tokens signed with them
      # stay verifiable while Keyora is down.
      LOG.error("could not fetch the JWKS: #{e.class}: #{e.message}")
    end

    def self.now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  end

  # --- Local verification (no call to Keyora per request) ---------------------

  # Verify an access token and return its claims.
  #
  # The five checks from examples/README.md happen in JWT.decode: algorithm
  # pinned to RS256, signature, exp, iss and aud. The sixth, token_use, follows it.
  def verify_token(token)
    claims, = JWT.decode(
      token, nil, true,
      algorithms: ["RS256"],      # never trust the algorithm named in the token
      jwks: Jwks.method(:call),   # picks the key by the token's `kid`
      iss: ISSUER, verify_iss: true,
      aud: CLIENT_ID, verify_aud: true, # refuse tokens issued to other applications
      required_claims: %w[exp iss aud]
    )
    # Keyora also signs OIDC ID tokens with the same key, issuer and audience.
    # An ID token says who signed in; it is not a permission to call this API,
    # so only tokens that declare themselves access tokens get through.
    raise JWT::DecodeError, "token_use is not \"access\"" unless claims["token_use"] == "access"

    claims
  rescue JWT::ExpiredSignature
    raise TokenExpired
  rescue JWT::DecodeError => e
    # Malformed token, bad signature, wrong issuer or audience, a missing claim,
    # an unknown key ID, or the JWKS could not be fetched. The reason goes to
    # the log only; the caller just learns that the token is invalid.
    LOG.warn("access token rejected: #{e.message}")
    raise TokenInvalid, e.message
  end
end
