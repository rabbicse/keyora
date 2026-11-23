<?php

namespace App\Services;

use App\Exceptions\KeyoraUnavailableException;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Http;

/**
 * Calls Keyora's REST API on behalf of this application.
 *
 * Every call carries the application's client_id and client_secret as HTTP
 * Basic credentials. That is why this code runs on the server: the secret
 * must never be sent to a browser or bundled into a mobile app.
 */
class KeyoraClient
{
    /**
     * POSTs a JSON body to Keyora. The response is Keyora's envelope:
     * "data" on success, "error" on failure.
     *
     * @param  array<string, mixed>  $body
     *
     * @throws \Illuminate\Http\Client\ConnectionException when Keyora cannot be reached
     */
    public function post(string $path, array $body): Response
    {
        return Http::baseUrl(config('keyora.url'))
            ->withBasicAuth((string) config('keyora.client_id'), (string) config('keyora.client_secret'))
            ->acceptJson()
            ->connectTimeout(5)
            ->timeout(10)
            // An empty PHP array would be sent as the JSON list "[]"; Keyora expects an object.
            ->post($path, $body === [] ? new \stdClass : $body);
    }

    /**
     * Asks Keyora for the live state of an access token. Costs one network
     * call per request, but sees logouts and role changes immediately.
     *
     * @return array<string, mixed> always has a boolean "active"
     */
    public function introspect(string $token): array
    {
        $response = $this->post('/api/v1/auth/introspect', ['token' => $token]);

        if ($response->status() !== 200 || ! is_array($response->json('data'))) {
            throw new KeyoraUnavailableException('introspection failed with status '.$response->status());
        }

        return $response->json('data');
    }
}
