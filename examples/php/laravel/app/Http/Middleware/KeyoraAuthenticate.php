<?php

namespace App\Http\Middleware;

use App\Exceptions\KeyoraAuthException;
use App\Services\KeyoraTokenVerifier;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Route middleware "keyora.auth": requires a valid Keyora access token.
 *
 * The token is verified locally (no call to Keyora per request). The
 * verified claims are then available to the rest of the request as
 * $request->attributes->get('keyora.claims').
 */
class KeyoraAuthenticate
{
    public const CLAIMS = 'keyora.claims';

    public function __construct(private readonly KeyoraTokenVerifier $verifier) {}

    public function handle(Request $request, Closure $next): Response
    {
        $request->attributes->set(self::CLAIMS, $this->claims($request));

        return $next($request);
    }

    /**
     * Returns the request's verified claims, verifying the token on first
     * use. The permission and role middleware call this too, so they work
     * with or without "keyora.auth" in front of them.
     *
     * @return array<string, mixed>
     *
     * @throws KeyoraAuthException
     */
    public function claims(Request $request): array
    {
        if (is_array($claims = $request->attributes->get(self::CLAIMS))) {
            return $claims;
        }

        $token = $request->bearerToken();
        if ($token === null || $token === '') {
            throw KeyoraAuthException::missingToken();
        }

        return $this->verifier->verify($token);
    }

    /**
     * @param  array<string, mixed>  $claims
     * @return list<string> the string values of a claim that should be a list
     */
    public static function stringList(array $claims, string $name): array
    {
        $value = $claims[$name] ?? null;

        return is_array($value) ? array_values(array_filter($value, 'is_string')) : [];
    }
}
