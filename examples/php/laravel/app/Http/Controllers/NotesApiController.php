<?php

namespace App\Http\Controllers;

use App\Exceptions\KeyoraAuthException;
use App\Http\Middleware\KeyoraAuthenticate;
use App\Services\KeyoraClient;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Symfony\Component\HttpFoundation\Response;

/**
 * The notes API. Authentication and authorization happen in the route
 * middleware (see routes/api.php); by the time a protected action runs, the
 * token has been verified and its claims are on the request.
 */
class NotesApiController extends Controller
{
    private const NOTES_KEY = 'example.notes';

    public function __construct(private readonly KeyoraClient $keyora) {}

    public function public(): JsonResponse
    {
        return response()->json(['message' => 'anyone can read this']);
    }

    // --- Backend for a frontend: forwarded to Keyora with the client secret ---

    public function register(Request $request): Response
    {
        return $this->forward($request, '/api/v1/auth/register');
    }

    public function login(Request $request): Response
    {
        return $this->forward($request, '/api/v1/auth/login');
    }

    public function refresh(Request $request): Response
    {
        return $this->forward($request, '/api/v1/auth/refresh');
    }

    public function logout(Request $request): Response
    {
        return $this->forward($request, '/api/v1/auth/logout');
    }

    // --- Resource server ---

    /** Any valid token. The answer comes from the token itself. */
    public function me(Request $request): JsonResponse
    {
        return response()->json($this->identity($request->attributes->get(KeyoraAuthenticate::CLAIMS)));
    }

    /**
     * Remote introspection instead of local verification: one network call
     * per request, but it sees logouts and role changes immediately.
     */
    public function meLive(Request $request): JsonResponse
    {
        $token = $request->bearerToken();
        if ($token === null || $token === '') {
            throw KeyoraAuthException::missingToken();
        }

        $live = $this->keyora->introspect($token);
        if (($live['active'] ?? false) !== true) {
            throw KeyoraAuthException::invalidToken('the access token is no longer active');
        }

        return response()->json($this->identity($live));
    }

    public function listNotes(): JsonResponse
    {
        return response()->json(['notes' => $this->notes()]);
    }

    public function createNote(Request $request): JsonResponse
    {
        $text = $request->json('text');
        if (! is_string($text) || $text === '') {
            return $this->error(400, 'validation_failed', 'text is required');
        }

        $claims = $request->attributes->get(KeyoraAuthenticate::CLAIMS);
        $note = ['text' => $text, 'author' => (string) ($claims['email'] ?? '')];

        // The application's own data, kept in the cache to keep the example
        // free of a database. The lock makes read-modify-write safe.
        Cache::lock(self::NOTES_KEY.'.lock', 5)->block(5, function () use ($note) {
            Cache::forever(self::NOTES_KEY, [...$this->notes(), $note]);
        });

        return response()->json($note, 201);
    }

    public function reports(): JsonResponse
    {
        return response()->json(['total_notes' => count($this->notes())]);
    }

    /** Relays a JSON request to Keyora and unwraps the response envelope. */
    private function forward(Request $request, string $path): Response
    {
        $body = json_decode($request->getContent(), true);
        if (! is_array($body) || ($body !== [] && array_is_list($body))) {
            return $this->error(400, 'invalid_json', 'request body must be a JSON object');
        }

        $response = $this->keyora->post($path, $body);

        if ($response->status() >= 400) {
            // Keyora's status and error code go back to the caller unchanged.
            return response()->json(['error' => $response->json('error') ?? [
                'code' => 'identity_error',
                'message' => 'the identity service returned an error',
            ]], $response->status());
        }
        if ($response->json('data') === null) {
            return response()->noContent($response->status()); // e.g. 204 after logout
        }

        return response()->json($response->json('data'), $response->status());
    }

    /**
     * @param  array<string, mixed>  $claims
     * @return array{sub: string, email: string, roles: list<string>, permissions: list<string>}
     */
    private function identity(array $claims): array
    {
        return [
            'sub' => (string) ($claims['sub'] ?? ''),
            'email' => (string) ($claims['email'] ?? ''),
            'roles' => KeyoraAuthenticate::stringList($claims, 'roles'),
            'permissions' => KeyoraAuthenticate::stringList($claims, 'permissions'),
        ];
    }

    /** @return list<array{text: string, author: string}> */
    private function notes(): array
    {
        return Cache::get(self::NOTES_KEY, [['text' => 'Welcome to Keyora', 'author' => 'system']]);
    }

    private function error(int $status, string $code, string $message): JsonResponse
    {
        return response()->json(['error' => ['code' => $code, 'message' => $message]], $status);
    }
}
