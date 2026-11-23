<?php

namespace App\Http\Middleware;

use App\Exceptions\KeyoraAuthException;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Route middleware "keyora.role": requires a valid access token that carries
 * AT LEAST ONE of the listed roles.
 *
 *     ->middleware('keyora.role:editor')
 *     ->middleware('keyora.role:editor,admin')
 */
class KeyoraRole
{
    public function __construct(private readonly KeyoraAuthenticate $auth) {}

    public function handle(Request $request, Closure $next, string ...$roles): Response
    {
        $claims = $this->auth->claims($request);
        $request->attributes->set(KeyoraAuthenticate::CLAIMS, $claims);

        if (array_intersect($roles, KeyoraAuthenticate::stringList($claims, 'roles')) === []) {
            throw KeyoraAuthException::forbidden('requires role: '.implode(' or ', $roles));
        }

        return $next($request);
    }
}
