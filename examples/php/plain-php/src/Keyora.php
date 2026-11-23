<?php

declare(strict_types=1);

/**
 * Calls Keyora's REST API on behalf of this application.
 *
 * Every call carries the application's client_id and client_secret as HTTP
 * Basic credentials. That is why this code runs on the server: the secret
 * must never be sent to a browser or bundled into a mobile app.
 */
final class Keyora
{
    public function __construct(
        private readonly string $baseUrl,
        private readonly string $clientId,
        private readonly string $clientSecret,
    ) {
    }

    /**
     * POSTs a JSON body and returns Keyora's status code and response
     * envelope. On success the envelope has "data", on failure "error".
     *
     * @param array<string, mixed>|object $body
     * @return array{0: int, 1: array<string, mixed>}
     * @throws RuntimeException when Keyora cannot be reached or answers with something that is not JSON
     */
    public function post(string $path, array|object $body): array
    {
        $ch = curl_init($this->baseUrl . $path);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => json_encode($body, JSON_THROW_ON_ERROR),
            CURLOPT_HTTPHEADER => ['Content-Type: application/json', 'Accept: application/json'],
            CURLOPT_HTTPAUTH => CURLAUTH_BASIC,
            CURLOPT_USERPWD => $this->clientId . ':' . $this->clientSecret,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT => 10,
        ]);
        $raw = curl_exec($ch);
        $status = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($raw === false) {
            throw new RuntimeException("keyora unreachable at {$this->baseUrl}: {$error}");
        }
        if ($raw === '') {
            return [$status, []]; // 204 No Content (logout), 202 Accepted
        }
        $envelope = json_decode((string) $raw, true);
        if (!is_array($envelope)) {
            throw new RuntimeException("unexpected response from keyora (status {$status})");
        }
        return [$status, $envelope];
    }

    /**
     * Asks Keyora for the live state of an access token. Costs one network
     * call per request, but sees logouts and role changes immediately.
     *
     * @return array<string, mixed> always has a boolean "active"
     */
    public function introspect(string $token): array
    {
        [$status, $envelope] = $this->post('/api/v1/auth/introspect', ['token' => $token]);
        if ($status !== 200 || !is_array($envelope['data'] ?? null)) {
            throw new RuntimeException("introspection failed with status {$status}");
        }
        return $envelope['data'];
    }
}
