<?php

namespace App\Services;

use App\Exceptions\KeyoraAuthException;
use App\Exceptions\KeyoraUnavailableException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Throwable;

/**
 * Verifies Keyora access tokens (RS256 JWTs) locally, with firebase/php-jwt.
 *
 * All six checks are required: pinned algorithm, signature against the JWKS
 * key named by "kid", expiry, issuer, audience and token use. php-jwt does
 * the first three; the others are checked here because php-jwt does not.
 */
class KeyoraTokenVerifier
{
    private const ALGORITHM = 'RS256';

    private const CACHE_KEY = 'keyora.jwks';

    /** Minimum seconds between JWKS refetches triggered by unknown key IDs,
     *  so that tokens with made-up kids cannot be used to hammer Keyora. */
    private const MIN_REFETCH_INTERVAL = 10;

    /**
     * @return array<string, mixed> the verified claims
     *
     * @throws KeyoraAuthException when the token must not be trusted
     * @throws KeyoraUnavailableException when the JWKS cannot be loaded
     */
    public function verify(string $token): array
    {
        // Read the header (unverified) only to pin the algorithm and to
        // know which key to look up.
        $header = $this->header($token);
        if (($header['alg'] ?? null) !== self::ALGORITHM) {
            throw KeyoraAuthException::invalidToken('the access token uses an unsupported algorithm');
        }
        $kid = $header['kid'] ?? null;
        if (! is_string($kid) || $kid === '') {
            throw KeyoraAuthException::invalidToken('the access token names no signing key');
        }

        $keys = $this->keysFor($kid);
        if (! isset($keys[$kid])) {
            throw KeyoraAuthException::invalidToken('the access token was signed with an unknown key');
        }

        try {
            // Every Key in $keys is bound to RS256, and php-jwt refuses a
            // token whose "alg" differs from its key's algorithm. decode()
            // verifies the signature, then "nbf", "iat" and "exp".
            JWT::$leeway = (int) config('keyora.leeway', 0);
            $claims = (array) JWT::decode($token, $keys);
        } catch (ExpiredException) {
            throw KeyoraAuthException::tokenExpired();
        } catch (Throwable $e) {
            throw KeyoraAuthException::invalidToken('the access token is invalid');
        }

        // php-jwt only checks "exp" when it is present. Refuse eternal tokens.
        if (! is_numeric($claims['exp'] ?? null)) {
            throw KeyoraAuthException::invalidToken('the access token has no expiry');
        }

        // Issuer: the token came from our Keyora.
        if (($claims['iss'] ?? null) !== config('keyora.issuer')) {
            throw KeyoraAuthException::invalidToken('the access token has the wrong issuer');
        }

        // Audience: the token was issued to this application, not to another
        // one on the same Keyora. "aud" may be a string or a list.
        $audiences = is_array($claims['aud'] ?? null) ? $claims['aud'] : [$claims['aud'] ?? null];
        if (! in_array(config('keyora.client_id'), $audiences, true)) {
            throw KeyoraAuthException::invalidToken('the access token was issued to another application');
        }

        // Token use: an OIDC ID token has the same issuer and audience as an
        // access token, so only this claim keeps it from being used as one.
        if (($claims['token_use'] ?? null) !== 'access') {
            throw KeyoraAuthException::invalidToken('the token is not an access token');
        }

        return $claims;
    }

    /** @return array<string, mixed> */
    private function header(string $token): array
    {
        $segments = explode('.', $token);
        if (count($segments) !== 3) {
            throw KeyoraAuthException::invalidToken('the access token is malformed');
        }

        try {
            $header = json_decode(JWT::urlsafeB64Decode($segments[0]), true);
        } catch (Throwable) {
            $header = null;
        }
        if (! is_array($header)) {
            throw KeyoraAuthException::invalidToken('the access token is malformed');
        }

        return $header;
    }

    /**
     * Returns Keyora's signing keys, indexed by key ID. The JWKS is cached;
     * it is fetched again when the cache has expired or when a token names
     * a key the cache does not have (Keyora rotated its key).
     *
     * @return array<string, \Firebase\JWT\Key>
     */
    private function keysFor(string $kid): array
    {
        $cached = Cache::get(self::CACHE_KEY);

        if (is_array($cached)) {
            $knowsKey = collect($cached['keys'])->contains(fn ($key) => ($key['kid'] ?? null) === $kid);
            if ($knowsKey || time() - $cached['fetched_at'] < self::MIN_REFETCH_INTERVAL) {
                return $this->parse($cached['keys']);
            }
        }

        $keys = $this->fetch();
        Cache::put(self::CACHE_KEY, ['fetched_at' => time(), 'keys' => $keys], (int) config('keyora.jwks_ttl', 300));

        return $this->parse($keys);
    }

    /**
     * @return list<array<string, mixed>>
     *
     * @throws KeyoraUnavailableException when Keyora cannot be reached (rendered as a 502)
     */
    private function fetch(): array
    {
        $url = config('keyora.url').'/.well-known/jwks.json';

        try {
            $response = Http::acceptJson()->connectTimeout(5)->timeout(10)->get($url);
        } catch (Throwable $e) {
            throw new KeyoraUnavailableException("cannot fetch JWKS from {$url}: {$e->getMessage()}", previous: $e);
        }
        if ($response->status() !== 200 || ! is_array($response->json('keys'))) {
            throw new KeyoraUnavailableException("unexpected JWKS response from {$url} (status {$response->status()})");
        }

        // Keep only RSA keys published for RS256 signatures. Without this
        // filter, a key that declares another "alg" would be bound to that
        // algorithm by JWK::parseKeySet.
        return collect($response->json('keys'))
            ->filter(fn ($key) => is_array($key)
                && ($key['kty'] ?? null) === 'RSA'
                && is_string($key['kid'] ?? null)
                && ($key['use'] ?? 'sig') === 'sig'
                && ($key['alg'] ?? self::ALGORITHM) === self::ALGORITHM)
            ->values()
            ->all();
    }

    /**
     * @param  list<array<string, mixed>>  $keys
     * @return array<string, \Firebase\JWT\Key>
     */
    private function parse(array $keys): array
    {
        if ($keys === []) {
            return [];
        }

        try {
            return JWK::parseKeySet(['keys' => $keys], self::ALGORITHM);
        } catch (Throwable $e) {
            Log::error('keyora: the JWKS could not be parsed: '.$e->getMessage());
            Cache::forget(self::CACHE_KEY);

            throw new KeyoraUnavailableException('the JWKS could not be parsed', previous: $e);
        }
    }
}
