# frozen_string_literal: true

# A notes API protected by Keyora, written with Sinatra.
#
# The application plays two roles:
#
#   - Backend for a frontend: /register, /login, /refresh and /logout forward
#     to Keyora with the application's client secret attached.
#   - Resource server: /me, /notes and /reports verify the access token
#     locally against Keyora's JWKS and check permissions and roles.
require "json"
require "sinatra"
require_relative "auth"
require_relative "keyora"

register Auth

set :server, :puma
set :bind, ENV.fetch("HOST", "127.0.0.1")
set :port, Integer(ENV.fetch("PORT", "9012"))
# Errors are answered by the handlers below, never by Sinatra's HTML pages.
set :show_exceptions, false
set :raise_errors, false

before { content_type :json }

# --- Errors: always {"error": {"code", "message"}} ----------------------------

helpers do
  def error_response(status, code, message)
    [status, JSON.generate(error: { code: code, message: message })]
  end

  def json_body
    body = JSON.parse(request.body.read)
    raise JSON::ParserError unless body.is_a?(Hash)

    body
  rescue JSON::ParserError
    raise Auth::ApiError.new(400, "invalid_json", "request body must be a JSON object")
  end

  # Relay the JSON request to Keyora and unwrap its `{data|error, meta}` envelope.
  # Keyora validates the fields; its status and error code are passed through unchanged.
  def forward(path)
    status, envelope = Keyora.post(path, json_body)
    return [status, JSON.generate(error: envelope["error"])] if status >= 400
    return status if envelope["data"].nil? # 204 from logout

    [status, JSON.generate(envelope["data"])]
  end
end

error Auth::ApiError do
  e = env["sinatra.error"]
  error_response(e.status, e.code, e.message)
end

error Keyora::Unavailable do
  Keyora::LOG.error("keyora call failed: #{env['sinatra.error'].message}")
  error_response(502, "identity_unavailable", "the identity service is unavailable")
end

# Only unmatched routes. (`not_found` would also replace the body of a 404
# passed through from Keyora.)
error Sinatra::NotFound do
  error_response(404, "not_found", "no such endpoint")
end

error do
  e = env["sinatra.error"]
  Keyora::LOG.error("unhandled error: #{e.class}: #{e.message}")
  error_response(500, "internal_error", "internal server error")
end

# --- Forwarded to Keyora --------------------------------------------------------

post("/register") { forward("/api/v1/auth/register") }
post("/login")    { forward("/api/v1/auth/login") }
post("/refresh")  { forward("/api/v1/auth/refresh") }
post("/logout")   { forward("/api/v1/auth/logout") }

# --- The application's own endpoints -------------------------------------------

NOTES = [{ text: "Welcome to Keyora", author: "system" }]
NOTES_LOCK = Mutex.new # Puma serves requests on several threads

get "/public" do
  JSON.generate(message: "anyone can read this")
end

# Authentication only: any valid token.
get "/me", authenticated: true do
  JSON.generate(claims)
end

# Remote introspection: one network call per request, but it sees logouts and
# role changes immediately.
get "/me/live" do
  state = Keyora.introspect(bearer_token)
  unless state["active"] == true
    raise Auth::ApiError.new(401, "invalid_token", "the access token is no longer active")
  end

  JSON.generate(
    sub: state["sub"].to_s,
    email: state["email"].to_s,
    roles: state["roles"] || [],
    permissions: state["permissions"] || []
  )
end

# Permission-based authorization.
get "/notes", permission: "notes:read" do
  JSON.generate(notes: NOTES_LOCK.synchronize { NOTES.dup })
end

post "/notes", permission: "notes:write" do
  text = json_body["text"]
  unless text.is_a?(String) && !text.empty?
    raise Auth::ApiError.new(400, "validation_failed", "text is required")
  end

  note = { text: text, author: claims["email"] }
  NOTES_LOCK.synchronize { NOTES << note }
  [201, JSON.generate(note)]
end

# Role-based authorization.
get "/reports", role: "editor" do
  JSON.generate(total_notes: NOTES_LOCK.synchronize { NOTES.size })
end
