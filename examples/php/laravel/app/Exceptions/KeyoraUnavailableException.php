<?php

namespace App\Exceptions;

use Illuminate\Http\JsonResponse;
use RuntimeException;

/**
 * Keyora could not be reached, or answered with something unusable. The
 * caller gets a 502; the detail stays in the log.
 */
class KeyoraUnavailableException extends RuntimeException
{
    public function render(): JsonResponse
    {
        return response()->json(
            ['error' => ['code' => 'identity_unavailable', 'message' => 'the identity service is unavailable']],
            502,
        );
    }
}
