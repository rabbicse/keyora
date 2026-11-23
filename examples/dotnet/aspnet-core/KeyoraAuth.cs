using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace KeyoraNotes;

/// <summary>
/// Local verification of Keyora access tokens with the JwtBearer handler, plus the
/// <c>RequirePermission</c> / <c>RequireRole</c> endpoint helpers.
/// </summary>
public static class KeyoraAuth
{
    public const string JwksHttpClient = "keyora-jwks";

    public static IServiceCollection AddKeyoraAuthentication(this IServiceCollection services, KeyoraSettings keyora)
    {
        services.AddHttpClient(JwksHttpClient, c => c.Timeout = TimeSpan.FromSeconds(10));
        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer();
        services.AddAuthorization();

        services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
            .Configure<IHttpClientFactory>((options, httpClients) =>
            {
                // Keep the claim names Keyora uses (sub, email, roles, permissions) instead
                // of translating them to the long XML-style names.
                options.MapInboundClaims = false;

                // Keyora publishes its public keys as a JWKS but has no OIDC discovery
                // document, so options.Authority cannot be used. This configuration
                // manager downloads the JWKS itself, caches it, and downloads it again
                // when the handler meets a `kid` it does not know (key rotation).
                options.ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                    keyora.JwksUrl,
                    new JwksRetriever(keyora.Issuer),
                    new HttpDocumentRetriever(httpClients.CreateClient(JwksHttpClient))
                    {
                        RequireHttps = keyora.JwksUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase),
                    })
                {
                    // At most one forced re-download per 30 seconds, so a flood of tokens
                    // with made-up key ids cannot turn into a flood of requests to Keyora.
                    RefreshInterval = TimeSpan.FromSeconds(30),
                };
                options.RefreshOnIssuerKeyNotFound = true;

                // The five checks: algorithm, signature, expiry, issuer, audience.
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
                    ValidateIssuerSigningKey = true,
                    RequireSignedTokens = true,
                    ValidateLifetime = true,
                    RequireExpirationTime = true,
                    // The default tolerance is 5 minutes, which would keep a 60-second
                    // Keyora token alive for 6.
                    ClockSkew = TimeSpan.Zero,
                    ValidateIssuer = true,
                    ValidIssuer = keyora.Issuer,
                    // Audience is our own client_id: tokens issued to other applications
                    // on the same Keyora are refused.
                    ValidateAudience = true,
                    ValidAudience = keyora.ClientId,
                    NameClaimType = "sub",
                    RoleClaimType = "roles",
                };

                options.Events = new JwtBearerEvents
                {
                    OnChallenge = async context =>
                    {
                        context.HandleResponse();
                        var failure = context.AuthenticateFailure;
                        var (status, code, message) = failure switch
                        {
                            null => (401, "missing_token", "a bearer access token is required"),
                            _ when Find<SecurityTokenExpiredException>(failure) is not null
                                => (401, "token_expired", "the access token has expired"),
                            // "No key for this token" is the token's fault if we hold
                            // Keyora's keys, and ours if we could not download them.
                            _ when Find<SecurityTokenSignatureKeyNotFoundException>(failure) is not null
                                && !await HasSigningKeys(context.Options, context.HttpContext.RequestAborted)
                                => (502, "identity_unavailable", "the identity service is unavailable"),
                            _ => (401, "invalid_token", "the access token is invalid"),
                        };
                        if (status == 401)
                        {
                            context.Response.Headers.WWWAuthenticate = "Bearer";
                        }
                        await WriteError(context.Response, status, code, message);
                    },
                    OnForbidden = context =>
                        WriteError(context.Response, 403, "forbidden", "the access token does not allow this request"),
                };
            });
        return services;
    }

    /// <summary>Requires a valid token that carries every listed permission.</summary>
    public static TBuilder RequirePermission<TBuilder>(this TBuilder endpoint, params string[] permissions)
        where TBuilder : IEndpointConventionBuilder =>
        endpoint.RequireAuthorization(policy =>
        {
            policy.RequireAuthenticatedUser();
            foreach (var permission in permissions)
            {
                policy.RequireClaim("permissions", permission);
            }
        });

    /// <summary>Requires a valid token that carries at least one of the listed roles.</summary>
    public static TBuilder RequireRole<TBuilder>(this TBuilder endpoint, params string[] roles)
        where TBuilder : IEndpointConventionBuilder =>
        endpoint.RequireAuthorization(policy => policy.RequireAuthenticatedUser().RequireClaim("roles", roles));

    /// <summary>The contract's error body: <c>{"error": {"code", "message"}}</c>.</summary>
    public static IResult Error(int status, string code, string message) =>
        Results.Json(new { error = new { code, message } }, statusCode: status);

    private static Task WriteError(HttpResponse response, int status, string code, string message)
    {
        response.StatusCode = status;
        return response.WriteAsJsonAsync(new { error = new { code, message } });
    }

    /// <summary>False when the JWKS has never been downloaded successfully (Keyora unreachable).</summary>
    private static async Task<bool> HasSigningKeys(JwtBearerOptions options, CancellationToken cancel)
    {
        try
        {
            var configuration = await options.ConfigurationManager!.GetConfigurationAsync(cancel);
            return configuration.SigningKeys.Count > 0;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }

    /// <summary>Looks for an exception of type T in an exception and everything it wraps.</summary>
    private static T? Find<T>(Exception? exception) where T : Exception => exception switch
    {
        null => null,
        T match => match,
        AggregateException many => many.InnerExceptions.Select(Find<T>).FirstOrDefault(e => e is not null),
        _ => Find<T>(exception.InnerException),
    };

    /// <summary>
    /// Builds the handler's configuration from Keyora's JWKS alone. The stock retriever
    /// expects an OIDC discovery document, which Keyora does not serve.
    /// </summary>
    private sealed class JwksRetriever(string issuer) : IConfigurationRetriever<OpenIdConnectConfiguration>
    {
        public async Task<OpenIdConnectConfiguration> GetConfigurationAsync(
            string address, IDocumentRetriever retriever, CancellationToken cancel)
        {
            var keys = new JsonWebKeySet(await retriever.GetDocumentAsync(address, cancel));
            var configuration = new OpenIdConnectConfiguration { Issuer = issuer, JwksUri = address, JsonWebKeySet = keys };
            foreach (var key in keys.GetSigningKeys())
            {
                configuration.SigningKeys.Add(key);
            }
            return configuration;
        }
    }
}
