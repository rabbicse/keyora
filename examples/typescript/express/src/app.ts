// A notes API protected by Keyora.
//
// The application plays two roles:
//
//   - Backend for a frontend: /register, /login, /refresh and /logout forward
//     to Keyora with the application's client secret attached.
//   - Resource server: /me, /notes and /reports verify the access token
//     locally against Keyora's JWKS and check permissions and roles.

import express, { type ErrorRequestHandler, type Express, type RequestHandler } from "express";

import { bearerToken, createAuth } from "./auth.js";
import type { Config } from "./config.js";
import { HttpError, identityUnavailable, invalidToken, missingToken } from "./errors.js";
import { KeyoraClient, KeyoraUnavailableError } from "./keyora.js";

interface Note {
  text: string;
  author: string;
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function createApp(config: Config): Express {
  const keyora = new KeyoraClient(config);
  const { authenticate, requirePermission, requireRole } = createAuth(config);
  const notes: Note[] = [{ text: "Welcome to Keyora", author: "system" }];

  const app = express();
  app.disable("x-powered-by");
  app.use(express.json({ limit: "64kb" }));

  // Relays a JSON request to Keyora and unwraps the response envelope:
  // `data` becomes the body on success, `error` is passed through unchanged,
  // and the status code is Keyora's in both cases.
  const forward = (path: string): RequestHandler => {
    return async (req, res) => {
      if (!isJsonObject(req.body)) {
        throw new HttpError(400, "invalid_json", "request body must be JSON");
      }
      const { status, body } = await keyora.post(path, req.body);
      if (status >= 400) {
        res.status(status).json({ error: body.error });
      } else if (body.data === undefined) {
        res.status(status).end();
      } else {
        res.status(status).json(body.data);
      }
    };
  };

  app.get("/public", (_req, res) => {
    res.json({ message: "anyone can read this" });
  });

  app.post("/register", forward("/api/v1/auth/register"));
  app.post("/login", forward("/api/v1/auth/login"));
  app.post("/refresh", forward("/api/v1/auth/refresh"));
  app.post("/logout", forward("/api/v1/auth/logout"));

  // Authentication only: any valid token. The answer comes from the token itself.
  app.get("/me", authenticate, (req, res) => {
    res.json(req.user);
  });

  // Remote introspection: one network call per request, but it sees logouts
  // and role changes immediately.
  app.get("/me/live", async (req, res) => {
    const token = bearerToken(req);
    if (!token) {
      throw missingToken();
    }
    const live = await keyora.introspect(token);
    if (!live.active) {
      throw invalidToken("the access token is no longer active");
    }
    res.json({
      sub: live.sub ?? "",
      email: live.email ?? "",
      roles: live.roles ?? [],
      permissions: live.permissions ?? [],
    });
  });

  // Permission-based authorization.
  app.get("/notes", authenticate, requirePermission("notes:read"), (_req, res) => {
    res.json({ notes });
  });

  app.post("/notes", authenticate, requirePermission("notes:write"), (req, res) => {
    const text = isJsonObject(req.body) ? req.body.text : undefined;
    if (typeof text !== "string" || text === "") {
      throw new HttpError(400, "validation_failed", "text is required");
    }
    const note: Note = { text, author: req.user?.email ?? "" };
    notes.push(note);
    res.status(201).json(note);
  });

  // Role-based authorization.
  app.get("/reports", authenticate, requireRole("editor"), (_req, res) => {
    res.json({ total_notes: notes.length });
  });

  app.use((_req, _res, next) => {
    next(new HttpError(404, "not_found", "no such endpoint"));
  });

  // Express 5 passes errors thrown by (async) handlers here.
  const errorHandler: ErrorRequestHandler = (err: unknown, _req, res, next) => {
    if (res.headersSent) {
      next(err);
      return;
    }
    let error: HttpError;
    if (err instanceof HttpError) {
      error = err;
    } else if (err instanceof KeyoraUnavailableError) {
      console.error(err);
      error = identityUnavailable();
    } else if (isBodyParserError(err)) {
      error =
        err.status === 413
          ? new HttpError(413, "payload_too_large", "request body is too large")
          : new HttpError(400, "invalid_json", "request body must be JSON");
    } else {
      console.error(err);
      error = new HttpError(500, "internal_error", "internal server error");
    }
    res.status(error.status).json({ error: { code: error.code, message: error.message } });
  };
  app.use(errorHandler);

  return app;
}

/** Errors raised by `express.json()` carry the HTTP status they should produce. */
function isBodyParserError(err: unknown): err is { status: number; type: string } {
  return (
    typeof err === "object" &&
    err !== null &&
    typeof (err as { type?: unknown }).type === "string" &&
    typeof (err as { status?: unknown }).status === "number" &&
    (err as { status: number }).status >= 400 &&
    (err as { status: number }).status < 500
  );
}
