// Local access-token verification and the authorization middleware built on it.
//
// No request to Keyora is made per call: the token's signature is checked
// against Keyora's public keys (JWKS), which are fetched once and cached.

import type { NextFunction, Request, RequestHandler, Response } from "express";
import { createRemoteJWKSet, errors as joseErrors, jwtVerify } from "jose";

import type { Config } from "./config.js";
import { forbidden, identityUnavailable, invalidToken, missingToken, tokenExpired } from "./errors.js";

/** The claims of a verified access token that this application uses. */
export interface AuthUser {
  sub: string;
  email: string;
  roles: string[];
  permissions: string[];
}

// Adds `req.user`, set by `authenticate`.
declare module "express-serve-static-core" {
  interface Request {
    user?: AuthUser;
  }
}

export interface Auth {
  /** Requires a valid access token and sets `req.user`. */
  authenticate: RequestHandler;
  /** Requires every listed permission. Use after `authenticate`. */
  requirePermission: (...permissions: string[]) => RequestHandler;
  /** Requires at least one of the listed roles. Use after `authenticate`. */
  requireRole: (...roles: string[]) => RequestHandler;
}

/** Returns the token from an `Authorization: Bearer <token>` header, if there is one. */
export function bearerToken(req: Request): string | undefined {
  const match = /^Bearer +(\S+)$/i.exec(req.get("authorization") ?? "");
  return match?.[1];
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
}

/**
 * True when verification failed because Keyora's key set could not be loaded
 * (network error, timeout, non-200 answer, malformed JWKS) rather than
 * because of anything in the token.
 */
function isJwksFetchFailure(err: unknown): boolean {
  if (!(err instanceof joseErrors.JOSEError)) return true; // fetch() rejected
  return (
    err instanceof joseErrors.JWKSTimeout ||
    err instanceof joseErrors.JWKSInvalid ||
    err.code === "ERR_JOSE_GENERIC" // jose's "Expected 200 OK from the JSON Web Key Set HTTP response"
  );
}

export function createAuth(config: Pick<Config, "keyoraUrl" | "issuer" | "clientId">): Auth {
  // Fetched on first use and cached. When a token names a key ID (`kid`) that
  // is not in the cache, the set is fetched again (at most once per
  // `cooldownDuration`), so key rotation in Keyora needs no restart here.
  const jwks = createRemoteJWKSet(new URL(`${config.keyoraUrl}/.well-known/jwks.json`), {
    cacheMaxAge: 5 * 60_000,
    cooldownDuration: 30_000,
    timeoutDuration: 5_000,
  });

  const authenticate: RequestHandler = async (req: Request, _res: Response, next: NextFunction) => {
    const token = bearerToken(req);
    if (!token) {
      next(missingToken());
      return;
    }
    try {
      // The first five checks from examples/README.md happen in this call:
      const { payload } = await jwtVerify(token, jwks, {
        algorithms: ["RS256"], // 1. the algorithm is pinned, not taken from the token
        //                        2. the signature is verified with the JWKS key matching `kid`
        issuer: config.issuer, // 4. iss
        audience: config.clientId, // 5. aud: tokens issued to other applications are refused
        requiredClaims: ["exp", "sub"], // 3. exp must be present (and is checked to be in the future)
      });
      // 6. token_use: an OIDC ID token has the same issuer and audience as an
      //    access token, so only this claim keeps it from being used as one.
      if (payload.token_use !== "access") {
        next(invalidToken());
        return;
      }
      req.user = {
        sub: payload.sub ?? "",
        email: typeof payload.email === "string" ? payload.email : "",
        roles: stringArray(payload.roles),
        permissions: stringArray(payload.permissions),
      };
      next();
    } catch (err) {
      if (err instanceof joseErrors.JWTExpired) {
        next(tokenExpired());
      } else if (isJwksFetchFailure(err)) {
        // The keys could not be fetched: that is our problem, not the caller's.
        console.error("could not load Keyora's JWKS:", err);
        next(identityUnavailable());
      } else {
        // Bad signature, wrong issuer or audience, unknown key, malformed
        // token... The caller is not told which.
        next(invalidToken());
      }
    }
  };

  const requirePermission = (...permissions: string[]): RequestHandler => {
    return (req, _res, next) => {
      const user = req.user;
      if (!user) {
        next(missingToken());
      } else if (permissions.every((p) => user.permissions.includes(p))) {
        next();
      } else {
        next(forbidden());
      }
    };
  };

  const requireRole = (...roles: string[]): RequestHandler => {
    return (req, _res, next) => {
      const user = req.user;
      if (!user) {
        next(missingToken());
      } else if (roles.some((r) => user.roles.includes(r))) {
        next();
      } else {
        next(forbidden());
      }
    };
  };

  return { authenticate, requirePermission, requireRole };
}
