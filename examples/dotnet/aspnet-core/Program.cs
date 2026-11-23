// A notes API protected by Keyora, as an ASP.NET Core minimal API.
//
// The application plays two roles:
//
//   - Backend for a frontend: /register, /login, /refresh and /logout forward to
//     Keyora with the application's client secret attached (KeyoraClient.cs).
//   - Resource server: /me, /notes and /reports verify the access token locally
//     against Keyora's JWKS and check permissions and roles (KeyoraAuth.cs).

using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using KeyoraNotes;
using Microsoft.Net.Http.Headers;

static string Env(string key, string fallback = "") =>
    Environment.GetEnvironmentVariable(key) is { Length: > 0 } value ? value : fallback;

var keyoraUrl = Env("KEYORA_URL", "http://localhost:8080").TrimEnd('/');
var keyora = new KeyoraSettings(keyoraUrl, Env("KEYORA_ISSUER", keyoraUrl), Env("KEYORA_CLIENT_ID"), Env("KEYORA_CLIENT_SECRET"));
if (keyora.ClientId == "" || keyora.ClientSecret == "")
{
    Console.Error.WriteLine("KEYORA_CLIENT_ID and KEYORA_CLIENT_SECRET are required (run examples/setup.sh, then load examples/.env)");
    return 1;
}

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls($"http://*:{Env("PORT", "9007")}");

builder.Services.AddKeyoraAuthentication(keyora);
builder.Services.AddHttpClient<KeyoraClient>(http =>
{
    http.BaseAddress = new Uri(keyora.Url + "/");
    http.Timeout = TimeSpan.FromSeconds(10);
    http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
        "Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{keyora.ClientId}:{keyora.ClientSecret}")));
});

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

var notes = new List<Note> { new("Welcome to Keyora", "system") };
var notesLock = new object();

app.MapGet("/public", () => new { message = "anyone can read this" });

// Forwarded to Keyora. Success bodies are the envelope's `data`; errors keep
// Keyora's status and error code.
app.MapPost("/register", (HttpRequest req, KeyoraClient k, CancellationToken ct) => Forward(req, k.RegisterAsync, ct));
app.MapPost("/login", (HttpRequest req, KeyoraClient k, CancellationToken ct) => Forward(req, k.LoginAsync, ct));
app.MapPost("/refresh", (HttpRequest req, KeyoraClient k, CancellationToken ct) => Forward(req, k.RefreshAsync, ct));
app.MapPost("/logout", (HttpRequest req, KeyoraClient k, CancellationToken ct) => Forward(req, k.LogoutAsync, ct));

// Authentication only: any valid token. Everything comes from the token's claims.
app.MapGet("/me", (ClaimsPrincipal user) => new
{
    sub = user.FindFirstValue("sub"),
    email = user.FindFirstValue("email"),
    roles = Values(user, "roles"),
    permissions = Values(user, "permissions"),
}).RequireAuthorization();

// Remote introspection: one network call per request, but it sees logouts and
// role changes immediately. The JwtBearer handler is not involved here.
app.MapGet("/me/live", async (HttpRequest req, KeyoraClient k, ILogger<KeyoraClient> log, CancellationToken ct) =>
{
    if (!AuthenticationHeaderValue.TryParse(req.Headers[HeaderNames.Authorization], out var header)
        || !"Bearer".Equals(header.Scheme, StringComparison.OrdinalIgnoreCase)
        || string.IsNullOrEmpty(header.Parameter))
    {
        return KeyoraAuth.Error(401, "missing_token", "a bearer access token is required");
    }
    try
    {
        var token = await k.IntrospectAsync(header.Parameter, ct);
        return token.Active
            ? Results.Json(new { sub = token.Sub, email = token.Email, roles = token.Roles ?? [], permissions = token.Permissions ?? [] })
            : KeyoraAuth.Error(401, "invalid_token", "the access token is no longer active");
    }
    catch (KeyoraUnavailableException ex)
    {
        log.LogError(ex, "Introspection failed");
        return KeyoraAuth.Error(502, "identity_unavailable", "the identity service is unavailable");
    }
});

// Permission-based authorization.
app.MapGet("/notes", () =>
{
    lock (notesLock)
    {
        return new { notes = notes.ToArray() };
    }
}).RequirePermission("notes:read");

app.MapPost("/notes", async (HttpRequest req, ClaimsPrincipal user) =>
{
    var text = await ReadJson(req) is { ValueKind: JsonValueKind.Object } body
        && body.TryGetProperty("text", out var t) && t.ValueKind == JsonValueKind.String ? t.GetString() : null;
    if (string.IsNullOrEmpty(text))
    {
        return KeyoraAuth.Error(400, "validation_failed", "text is required");
    }
    var note = new Note(text, user.FindFirstValue("email") ?? "");
    lock (notesLock)
    {
        notes.Add(note);
    }
    return Results.Json(note, statusCode: 201);
}).RequirePermission("notes:write");

// Role-based authorization.
app.MapGet("/reports", () =>
{
    lock (notesLock)
    {
        return new Dictionary<string, int> { ["total_notes"] = notes.Count };
    }
}).RequireRole("editor");

app.Logger.LogInformation("Notes API starting (Keyora at {KeyoraUrl}, issuer {Issuer})", keyora.Url, keyora.Issuer);
app.Run();
return 0;

// Relays a JSON request body to Keyora and unwraps the envelope.
async Task<IResult> Forward(HttpRequest request, Func<JsonElement, CancellationToken, Task<KeyoraResponse>> call, CancellationToken ct)
{
    if (await ReadJson(request) is not { } body)
    {
        return KeyoraAuth.Error(400, "invalid_json", "request body must be JSON");
    }
    try
    {
        var res = await call(body, ct);
        if (res.Status >= 400)
        {
            return Results.Json(new { error = res.Error }, statusCode: res.Status);
        }
        return res.Data is { } data ? Results.Json(data, statusCode: res.Status) : Results.StatusCode(res.Status);
    }
    catch (KeyoraUnavailableException ex)
    {
        app.Logger.LogError(ex, "Call to Keyora failed");
        return KeyoraAuth.Error(502, "identity_unavailable", "the identity service is unavailable");
    }
}

// Reads the body as JSON whatever the Content-Type; null if it is not valid JSON.
static async Task<JsonElement?> ReadJson(HttpRequest request)
{
    try
    {
        return await JsonSerializer.DeserializeAsync<JsonElement>(request.Body, cancellationToken: request.HttpContext.RequestAborted);
    }
    catch (JsonException)
    {
        return null;
    }
}

// Keyora's `roles` and `permissions` are JSON arrays; the handler turns each
// element into its own claim.
static string[] Values(ClaimsPrincipal user, string claimType) =>
    user.FindAll(claimType).Select(c => c.Value).ToArray();

record Note(string Text, string Author);
