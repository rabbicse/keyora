<?php

namespace App\Exceptions;

use Illuminate\Http\JsonResponse;
use RuntimeException;

/**
 * A request refused by the Keyora middleware. Laravel calls render() on
 * exceptions that define it, which produces the error shape every example
 * uses: {"error": {"code": "...", "message": "..."}}.
 */
class KeyoraAuthException extends RuntimeException
{
    public function __construct(
        public readonly int $status,
        public readonly string $errorCode,
        string $message,
    ) {
        parent::__construct($message);
    }

    public static function missingToken(): self
    {
        return new self(401, 'missing_token', 'a bearer access token is required');
    }

    public static function invalidToken(string $message = 'the access token is invalid'): self
    {
        return new self(401, 'invalid_token', $message);
    }

    public static function tokenExpired(): self
    {
        return new self(401, 'token_expired', 'the access token has expired');
    }

    public static function forbidden(string $message): self
    {
        return new self(403, 'forbidden', $message);
    }

    public function render(): JsonResponse
    {
        return response()->json(
            ['error' => ['code' => $this->errorCode, 'message' => $this->getMessage()]],
            $this->status,
        );
    }

    /** Refused requests are expected; do not fill the log with them. */
    public function report(): bool
    {
        return true;
    }
}
