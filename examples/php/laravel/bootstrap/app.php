<?php

use App\Http\Middleware\KeyoraAuthenticate;
use App\Http\Middleware\KeyoraPermission;
use App\Http\Middleware\KeyoraRole;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Request;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        // Only the stateless API routes, at the root instead of under /api.
        // No "web" routes are registered, so nothing starts a session or
        // expects a CSRF token.
        api: __DIR__.'/../routes/api.php',
        apiPrefix: '',
        commands: __DIR__.'/../routes/console.php',
    )
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->alias([
            'keyora.auth' => KeyoraAuthenticate::class,
            'keyora.permission' => KeyoraPermission::class,
            'keyora.role' => KeyoraRole::class,
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        // Every error is JSON in the shape {"error": {"code", "message"}}.
        // KeyoraAuthException (401/403) and KeyoraUnavailableException (502)
        // render themselves; the handlers below cover everything else.
        $error = fn (int $status, string $code, string $message) => response()->json(
            ['error' => ['code' => $code, 'message' => $message]],
            $status,
        );

        // Keyora could not be reached.
        $exceptions->render(fn (ConnectionException $e, Request $request) => $error(
            502, 'identity_unavailable', 'the identity service is unavailable',
        ));

        // 404, 405 and other HTTP errors raised by the framework.
        $exceptions->render(fn (HttpExceptionInterface $e, Request $request) => $error(
            $e->getStatusCode(),
            match ($e->getStatusCode()) {
                404 => 'not_found',
                405 => 'method_not_allowed',
                default => 'http_error',
            },
            match ($e->getStatusCode()) {
                404 => 'no such endpoint',
                405 => 'method not allowed',
                default => 'the request could not be handled',
            },
        ));

        // Anything unexpected. The detail goes to the log, not to the caller.
        $exceptions->render(fn (Throwable $e, Request $request) => $error(
            500, 'internal_error', config('app.debug') ? $e->getMessage() : 'internal server error',
        ));
    })->create();
