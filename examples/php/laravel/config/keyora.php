<?php

$url = rtrim((string) env('KEYORA_URL', 'http://localhost:8080'), '/');

return [

    // Where this application reaches Keyora (API calls and JWKS).
    'url' => $url,

    // The "iss" value required in tokens. It equals Keyora's own
    // KEYORA_ISSUER setting. It differs from "url" when this application
    // reaches Keyora on an internal address, such as from inside a container.
    'issuer' => env('KEYORA_ISSUER') ?: $url,

    // The application's client ID. Also the "aud" value required in tokens.
    'client_id' => env('KEYORA_CLIENT_ID'),

    // The application's secret. Server-side only: never expose it to a
    // browser, a mobile app or a public repository.
    'client_secret' => env('KEYORA_CLIENT_SECRET'),

    // Seconds the JWKS is cached before it is fetched again.
    'jwks_ttl' => 300,

    // Seconds of clock difference tolerated between this server and Keyora.
    'leeway' => 0,

];
