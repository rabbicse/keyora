<?php

declare(strict_types=1);

/**
 * Keyora's public signing keys (JWKS), cached between requests.
 *
 * PHP shares no memory between requests, so the key set is kept in APCu when
 * that extension is loaded and in a file under the system temp directory
 * otherwise. Keys are refetched when the cache is older than TTL seconds, or
 * when a token names a "kid" the cache does not have (Keyora rotated its key).
 */
final class Jwks
{
    /** Seconds a fetched key set is trusted without asking again. */
    private const TTL = 300;
    /** Minimum seconds between refetches triggered by unknown key IDs, so
     *  that tokens with made-up kids cannot be used to hammer Keyora. */
    private const MIN_REFETCH_INTERVAL = 10;

    private readonly string $cacheKey;

    public function __construct(private readonly string $url)
    {
        $this->cacheKey = 'keyora_jwks_' . hash('sha256', $url);
    }

    /**
     * Returns the RS256 signing key with this ID, or null if Keyora has none.
     *
     * @return array<string, mixed>|null
     * @throws RuntimeException when no key set is cached and Keyora cannot be reached
     */
    public function find(string $kid): ?array
    {
        $cached = $this->read();
        $age = $cached === null ? PHP_INT_MAX : time() - $cached['fetched_at'];

        if ($cached !== null && $age < self::TTL) {
            $key = self::pick($cached['keys'], $kid);
            if ($key !== null || $age < self::MIN_REFETCH_INTERVAL) {
                return $key;
            }
        }

        try {
            $keys = $this->fetch();
        } catch (RuntimeException $e) {
            // Keyora is unreachable. Keep working with the keys we already
            // have rather than rejecting every request.
            if ($cached !== null) {
                error_log('keyora: ' . $e->getMessage() . '; using cached keys');
                return self::pick($cached['keys'], $kid);
            }
            throw $e;
        }
        $this->write(['fetched_at' => time(), 'keys' => $keys]);
        return self::pick($keys, $kid);
    }

    /**
     * @param list<array<string, mixed>> $keys
     * @return array<string, mixed>|null
     */
    private static function pick(array $keys, string $kid): ?array
    {
        foreach ($keys as $key) {
            if (($key['kid'] ?? null) !== $kid || ($key['kty'] ?? null) !== 'RSA') {
                continue;
            }
            // Ignore keys published for anything other than RS256 signatures.
            if (($key['use'] ?? 'sig') !== 'sig' || ($key['alg'] ?? 'RS256') !== 'RS256') {
                continue;
            }
            return $key;
        }
        return null;
    }

    /** @return list<array<string, mixed>> */
    private function fetch(): array
    {
        $ch = curl_init($this->url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_HTTPHEADER => ['Accept: application/json'],
        ]);
        $raw = curl_exec($ch);
        $status = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($raw === false) {
            throw new RuntimeException("cannot fetch JWKS from {$this->url}: {$error}");
        }
        $body = json_decode((string) $raw, true);
        if ($status !== 200 || !is_array($body) || !is_array($body['keys'] ?? null)) {
            throw new RuntimeException("unexpected JWKS response from {$this->url} (status {$status})");
        }
        return array_values(array_filter($body['keys'], 'is_array'));
    }

    /** @return array{fetched_at: int, keys: list<array<string, mixed>>}|null */
    private function read(): ?array
    {
        if (self::apcu()) {
            $value = apcu_fetch($this->cacheKey, $found);
            return $found && is_array($value) ? $value : null;
        }
        $raw = @file_get_contents($this->cacheFile());
        $value = $raw === false ? null : json_decode($raw, true);
        return is_array($value) && is_int($value['fetched_at'] ?? null) && is_array($value['keys'] ?? null)
            ? $value
            : null;
    }

    /** @param array{fetched_at: int, keys: list<array<string, mixed>>} $value */
    private function write(array $value): void
    {
        if (self::apcu()) {
            apcu_store($this->cacheKey, $value);
            return;
        }
        // Write to a temporary file and rename it, so that a concurrent
        // request never reads a half-written cache. Only public keys are
        // stored here; there is nothing secret in this file.
        $tmp = $this->cacheFile() . '.' . bin2hex(random_bytes(6)) . '.tmp';
        if (@file_put_contents($tmp, json_encode($value)) !== false) {
            @rename($tmp, $this->cacheFile());
        }
    }

    private function cacheFile(): string
    {
        return sys_get_temp_dir() . DIRECTORY_SEPARATOR . $this->cacheKey . '.json';
    }

    private static function apcu(): bool
    {
        return function_exists('apcu_enabled') && apcu_enabled();
    }
}
