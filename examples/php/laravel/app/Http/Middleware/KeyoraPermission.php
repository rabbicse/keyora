<?php

namespace App\Http\Middleware;

use App\Exceptions\KeyoraAuthException;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Route middleware "keyora.permission": requires a valid access token that
 * carries ALL of the listed permissions.
 *
 *     ->middleware('keyora.permission:notes:read')
 *     ->middleware('keyora.permission:notes:read,notes:write')
 *
 * Laravel splits middleware parameters on commas, so the colon inside a
 * permission name is safe.
 */
class KeyoraPermission
{
    public function __construct(private readonly KeyoraAuthenticate $auth) {}

    public function handle(Request $request, Closure $next, string ...$permissions): Response
    {
        $claims = $this->auth->claims($request);
        $request->attributes->set(KeyoraAuthenticate::CLAIMS, $claims);

        $missing = array_diff($permissions, KeyoraAuthenticate::stringList($claims, 'permissions'));
        if ($missing !== []) {
            throw KeyoraAuthException::forbidden('missing permission: '.implode(', ', $missing));
        }

        return $next($request);
    }
}
