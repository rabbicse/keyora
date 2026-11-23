<?php

declare(strict_types=1);

// A notes API protected by Keyora, in plain PHP: no framework, no Composer.
//
// The application plays two roles:
//
//   - Backend for a frontend: /register, /login, /refresh and /logout forward
//     to Keyora with the application's client secret attached.
//   - Resource server: /me, /notes and /reports verify the access token
//     locally against Keyora's JWKS and check permissions and roles.
//
// Run it with PHP's built-in server, using this file as the router script:
//
//     php -S 0.0.0.0:9008 index.php

require __DIR__ . '/src/Jwks.php';
require __DIR__ . '/src/Jwt.php';
require __DIR__ . '/src/Keyora.php';
require __DIR__ . '/src/Notes.php';

function env(string $key, string $fallback = ''): string
{
    $value = getenv($key);
    return $value === false || $value === '' ? $fallback : $value;
}

/** Sends a JSON response and ends the request. */
function respond(int $status, mixed $body): never
{
    http_response_code($status);
    header('Content-Type: application/json');
    echo json_encode($body, JSON_UNESCAPED_SLASHES);
    exit;
}

/** Sends an error in the shape every example uses. */
function deny(int $status, string $code, string $message): never
{
    respond($status, ['error' => ['code' => $code, 'message' => $message]]);
}

/** Reads the request body as a JSON object, or answers 400. */
function jsonBody(): stdClass
{
    $body = json_decode((string) file_get_contents('php://input', false, null, 0, 1 << 16));
    if (!$body instanceof stdClass) {
        deny(400, 'invalid_json', 'request body must be a JSON object');
    }
    return $body;
}

/** Returns the token from "Authorization: Bearer <token>", or answers 401. */
function bearerToken(): string
{
    $header = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (preg_match('/\ABearer +(\S+)\z/i', trim($header), $m) !== 1) {
        deny(401, 'missing_token', 'a bearer access token is required');
    }
    return $m[1];
}

/** @return list<string> the string values of a claim that should be a list */
function stringList(mixed $value): array
{
    return is_array($value) ? array_values(array_filter($value, 'is_string')) : [];
}

$keyoraUrl = rtrim(env('KEYORA_URL', 'http://localhost:8080'), '/');
$clientId = env('KEYORA_CLIENT_ID');
$clientSecret = env('KEYORA_CLIENT_SECRET');
if ($clientId === '' || $clientSecret === '') {
    error_log('KEYORA_CLIENT_ID and KEYORA_CLIENT_SECRET are required (run examples/setup.sh)');
    deny(500, 'misconfigured', 'the application is not configured');
}

$keyora = new Keyora($keyoraUrl, $clientId, $clientSecret);
$notes = new Notes();
// The verifier checks signature, expiry, issuer and audience. Audience is our
// own client_id: tokens issued to other applications are refused.
$jwt = new Jwt(
    new Jwks($keyoraUrl . '/.well-known/jwks.json'),
    env('KEYORA_ISSUER', $keyoraUrl),
    $clientId,
);

/**
 * Verifies the request's access token locally and returns its claims.
 * No call to Keyora is made (apart from fetching the JWKS when the cache is cold).
 *
 * @return array<string, mixed>
 */
$authenticate = function () use ($jwt): array {
    $token = bearerToken();
    try {
        return $jwt->verify($token);
    } catch (TokenException $e) {
        deny(401, $e->errorCode, $e->getMessage());
    } catch (RuntimeException $e) {
        error_log('keyora: ' . $e->getMessage());
        deny(502, 'identity_unavailable', 'the identity service is unavailable');
    }
};

/** Requires every listed permission. */
$requirePermission = function (string ...$required) use ($authenticate): array {
    $claims = $authenticate();
    if (array_diff($required, stringList($claims['permissions'] ?? null)) !== []) {
        deny(403, 'forbidden', 'missing permission: ' . implode(', ', $required));
    }
    return $claims;
};

/** Requires at least one of the listed roles. */
$requireRole = function (string ...$anyOf) use ($authenticate): array {
    $claims = $authenticate();
    if (array_intersect($anyOf, stringList($claims['roles'] ?? null)) === []) {
        deny(403, 'forbidden', 'requires role: ' . implode(' or ', $anyOf));
    }
    return $claims;
};

/** Relays a JSON request to Keyora and unwraps the response envelope. */
$forward = function (string $path) use ($keyora): never {
    $body = jsonBody();
    try {
        [$status, $envelope] = $keyora->post($path, $body);
    } catch (RuntimeException $e) {
        error_log('keyora: ' . $e->getMessage());
        deny(502, 'identity_unavailable', 'the identity service is unavailable');
    }
    if ($status >= 400) {
        // Keyora's status and error code go back to the caller unchanged.
        respond($status, ['error' => $envelope['error'] ?? ['code' => 'identity_error', 'message' => 'the identity service returned an error']]);
    }
    if (!isset($envelope['data'])) {
        ini_set('default_mimetype', ''); // no body, so no Content-Type
        http_response_code($status); // e.g. 204 after logout
        exit;
    }
    respond($status, $envelope['data']);
};

$routes = [
    'GET /public' => fn () => respond(200, ['message' => 'anyone can read this']),

    'POST /register' => fn () => $forward('/api/v1/auth/register'),
    'POST /login' => fn () => $forward('/api/v1/auth/login'),
    'POST /refresh' => fn () => $forward('/api/v1/auth/refresh'),
    'POST /logout' => fn () => $forward('/api/v1/auth/logout'),

    // Authentication only: any valid token.
    'GET /me' => function () use ($authenticate) {
        $claims = $authenticate();
        respond(200, [
            'sub' => $claims['sub'] ?? '',
            'email' => $claims['email'] ?? '',
            'roles' => stringList($claims['roles'] ?? null),
            'permissions' => stringList($claims['permissions'] ?? null),
        ]);
    },

    // Remote introspection: one network call per request, but it sees
    // logouts and role changes immediately.
    'GET /me/live' => function () use ($keyora) {
        $token = bearerToken();
        try {
            $live = $keyora->introspect($token);
        } catch (RuntimeException $e) {
            error_log('keyora: ' . $e->getMessage());
            deny(502, 'identity_unavailable', 'the identity service is unavailable');
        }
        if (($live['active'] ?? false) !== true) {
            deny(401, 'invalid_token', 'the access token is no longer active');
        }
        respond(200, [
            'sub' => $live['sub'] ?? '',
            'email' => $live['email'] ?? '',
            'roles' => stringList($live['roles'] ?? null),
            'permissions' => stringList($live['permissions'] ?? null),
        ]);
    },

    // Permission-based authorization.
    'GET /notes' => function () use ($requirePermission, $notes) {
        $requirePermission('notes:read');
        respond(200, ['notes' => $notes->all()]);
    },
    'POST /notes' => function () use ($requirePermission, $notes) {
        $claims = $requirePermission('notes:write');
        $text = jsonBody()->text ?? null;
        if (!is_string($text) || $text === '') {
            deny(400, 'validation_failed', 'text is required');
        }
        $note = ['text' => $text, 'author' => (string) ($claims['email'] ?? '')];
        $notes->add($note);
        respond(201, $note);
    },

    // Role-based authorization.
    'GET /reports' => function () use ($requireRole, $notes) {
        $requireRole('editor');
        respond(200, ['total_notes' => count($notes->all())]);
    },
];

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

if (isset($routes["$method $path"])) {
    $routes["$method $path"]();
}
foreach (array_keys($routes) as $route) {
    if (str_ends_with($route, " $path")) {
        deny(405, 'method_not_allowed', 'method not allowed');
    }
}
deny(404, 'not_found', 'no such endpoint');
