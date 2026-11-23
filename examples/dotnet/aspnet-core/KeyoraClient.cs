using System.Text.Json;
using System.Text.Json.Serialization;

namespace KeyoraNotes;

/// <summary>Settings read from the environment in Program.cs.</summary>
public sealed record KeyoraSettings(string Url, string Issuer, string ClientId, string ClientSecret)
{
    public string JwksUrl => Url + "/.well-known/jwks.json";
}

/// <summary>Keyora could not be reached, or answered with something that is not its JSON envelope.</summary>
public sealed class KeyoraUnavailableException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>
/// Keyora's answer to one call: the HTTP status and the two halves of its
/// <c>{data | error, meta}</c> envelope. Exactly one of them is set, or neither for 204.
/// </summary>
public readonly record struct KeyoraResponse(int Status, JsonElement? Data, JsonElement? Error);

/// <summary>The live state of a token as reported by Keyora.</summary>
public sealed record Introspection(
    [property: JsonPropertyName("active")] bool Active,
    [property: JsonPropertyName("sub")] string? Sub,
    [property: JsonPropertyName("email")] string? Email,
    [property: JsonPropertyName("roles")] string[]? Roles,
    [property: JsonPropertyName("permissions")] string[]? Permissions);

/// <summary>
/// Calls Keyora's REST API on behalf of this application. Every request carries the
/// client id and secret as HTTP Basic credentials (set once on the HttpClient in
/// Program.cs), which is why this class lives on the server and never in a browser.
/// </summary>
public sealed class KeyoraClient(HttpClient http)
{
    private sealed record Envelope(
        [property: JsonPropertyName("data")] JsonElement? Data,
        [property: JsonPropertyName("error")] JsonElement? Error);

    public Task<KeyoraResponse> RegisterAsync(JsonElement body, CancellationToken ct) => PostAsync("api/v1/auth/register", body, ct);
    public Task<KeyoraResponse> LoginAsync(JsonElement body, CancellationToken ct) => PostAsync("api/v1/auth/login", body, ct);
    public Task<KeyoraResponse> RefreshAsync(JsonElement body, CancellationToken ct) => PostAsync("api/v1/auth/refresh", body, ct);
    public Task<KeyoraResponse> LogoutAsync(JsonElement body, CancellationToken ct) => PostAsync("api/v1/auth/logout", body, ct);

    /// <summary>Asks Keyora whether an access token is valid right now.</summary>
    public async Task<Introspection> IntrospectAsync(string token, CancellationToken ct)
    {
        var res = await PostAsync("api/v1/auth/introspect", new { token }, ct);
        if (res.Status != StatusCodes.Status200OK || res.Data is not { } data)
        {
            throw new KeyoraUnavailableException($"introspection failed with status {res.Status}");
        }
        return data.Deserialize<Introspection>()
            ?? throw new KeyoraUnavailableException("introspection returned no data");
    }

    /// <summary>
    /// Posts a JSON body and returns Keyora's status and envelope. Non-2xx answers are
    /// returned, not thrown, so the caller can pass them through unchanged.
    /// </summary>
    private async Task<KeyoraResponse> PostAsync<T>(string path, T body, CancellationToken ct)
    {
        try
        {
            using var res = await http.PostAsJsonAsync(path, body, ct);
            var raw = await res.Content.ReadAsByteArrayAsync(ct);
            if (raw.Length == 0)
            {
                return new KeyoraResponse((int)res.StatusCode, null, null);
            }
            var envelope = JsonSerializer.Deserialize<Envelope>(raw);
            return new KeyoraResponse((int)res.StatusCode, envelope?.Data, envelope?.Error);
        }
        catch (HttpRequestException ex)
        {
            throw new KeyoraUnavailableException("keyora unreachable: " + ex.Message, ex);
        }
        catch (OperationCanceledException ex) when (!ct.IsCancellationRequested)
        {
            throw new KeyoraUnavailableException("keyora did not answer in time", ex);
        }
        catch (JsonException ex)
        {
            throw new KeyoraUnavailableException("unexpected response from keyora: " + ex.Message, ex);
        }
    }
}
