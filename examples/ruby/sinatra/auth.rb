# frozen_string_literal: true

# Sinatra extension for authentication and authorization.
#
#     register Auth
#
#     get "/notes", permission: "notes:read" do
#       claims["email"]
#     end
require "sinatra/base"
require_relative "keyora"

module Auth
  # An error answered as `{"error": {"code", "message"}}` with the given status.
  class ApiError < StandardError
    attr_reader :status, :code

    def initialize(status, code, message)
      super(message)
      @status = status
      @code = code
    end
  end

  module Helpers
    # Extract the token from `Authorization: Bearer <token>`.
    def bearer_token
      scheme, token = request.env["HTTP_AUTHORIZATION"].to_s.split(" ", 2)
      token = token.to_s.strip
      unless scheme.to_s.casecmp?("bearer") && !token.empty?
        raise ApiError.new(401, "missing_token", "a bearer access token is required")
      end

      token
    end

    # Verify the access token locally (once per request) and return its claims.
    def claims
      @claims ||= begin
        verified = Keyora.verify_token(bearer_token)
        {
          "sub" => verified["sub"].to_s,
          "email" => verified["email"].to_s,
          "roles" => string_list(verified["roles"]),
          "permissions" => string_list(verified["permissions"])
        }
      rescue Keyora::TokenExpired
        raise ApiError.new(401, "token_expired", "the access token has expired")
      rescue Keyora::TokenInvalid
        raise ApiError.new(401, "invalid_token", "the access token is invalid")
      end
    end

    def forbidden!
      raise ApiError.new(403, "forbidden", "you do not have permission to perform this action")
    end

    private

    def string_list(value)
      value.is_a?(Array) ? value.grep(String) : []
    end
  end

  def self.registered(app)
    app.helpers Helpers

    # Route conditions. Each one authenticates first (401) and then authorizes (403).

    # authenticated: true -- any valid access token.
    app.set(:authenticated) { |_| condition { claims } }

    # permission: "a" or permission: %w[a b] -- every listed permission is required.
    app.set(:permission) do |*required|
      condition { forbidden! unless (required.flatten - claims["permissions"]).empty? }
    end

    # role: "a" or role: %w[a b] -- any one of the listed roles is enough.
    app.set(:role) do |*allowed|
      condition { forbidden! unless allowed.flatten.intersect?(claims["roles"]) }
    end
  end
end
