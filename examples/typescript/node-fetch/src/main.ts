// A walkthrough of the Keyora HTTP API using nothing but Node's built-in
// `fetch` and `node:crypto`. It prints every request and response, verifies
// the access token by hand, and exits non-zero if any step gives an
// unexpected result.
//
// In a real application, verify tokens with a maintained JWT library (the
// Express example next to this one uses `jose`). The verification is written
// out here so every check is visible.

import { constants, createPublicKey, randomBytes, verify as verifySignature, type KeyObject } from "node:crypto";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const KEYORA_URL = (process.env.KEYORA_URL || "http://localhost:8080").replace(/\/+$/, "");
const ISSUER = process.env.KEYORA_ISSUER || KEYORA_URL;
const CLIENT_ID = process.env.KEYORA_CLIENT_ID ?? "";
const CLIENT_SECRET = process.env.KEYORA_CLIENT_SECRET ?? "";

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

type Json = Record<string, unknown>;

interface ApiResponse {
  status: number;
  /** The `data` member of Keyora's envelope (empty object when absent). */
  data: Json;
  /** The `error.code` member of Keyora's envelope, if the call failed. */
  errorCode: string | undefined;
  errorMessage: string | undefined;
}

type Credentials = { basic: true } | { bearer: string } | undefined;

function isObject(value: unknown): value is Json {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Shortens tokens and secrets so the output stays readable. */
function redact(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redact);
  if (!isObject(value)) return value;
  const out: Json = {};
  for (const [key, v] of Object.entries(value)) {
    if (typeof v === "string" && /token|password|secret/.test(key) && key !== "token_type") {
      out[key] = v.length > 24 ? `${v.slice(0, 16)}...(${v.length} chars)` : "***";
    } else {
      out[key] = redact(v);
    }
  }
  return out;
}

/**
 * Calls Keyora and prints the exchange. Every /api/v1 answer is an envelope:
 * {"data": ...} on success, {"error": {"code", "message"}} on failure.
 */
async function keyora(method: "GET" | "POST", path: string, body?: Json, credentials?: Credentials): Promise<ApiResponse> {
  const headers: Record<string, string> = { Accept: "application/json" };
  let auth = "";
  if (credentials && "basic" in credentials) {
    // HTTP Basic: client_id as the username, client_secret as the password.
    headers.Authorization = "Basic " + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64");
    auth = "  [Authorization: Basic client_id:client_secret]";
  } else if (credentials) {
    headers.Authorization = `Bearer ${credentials.bearer}`;
    auth = "  [Authorization: Bearer <token>]";
  }
  if (body) headers["Content-Type"] = "application/json";

  console.log(`  > ${method} ${path}${auth}`);
  if (body) console.log(`    ${JSON.stringify(redact(body))}`);

  let res: Response;
  try {
    res = await fetch(KEYORA_URL + path, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(10_000),
    });
  } catch (cause) {
    throw new Error(`Keyora is not reachable at ${KEYORA_URL} (${method} ${path})`, { cause });
  }

  const text = await res.text();
  let envelope: Json = {};
  if (text !== "") {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new Error(`${method} ${path} answered ${res.status} with a body that is not JSON: ${text.slice(0, 120)}`);
    }
    if (isObject(parsed)) envelope = parsed;
  }
  const shown = envelope.error ?? envelope.data ?? (isObject(envelope) && Object.keys(envelope).length ? envelope : undefined);
  console.log(`  < ${res.status}${shown === undefined ? " (no body)" : " " + JSON.stringify(redact(shown))}`);

  const error = isObject(envelope.error) ? envelope.error : undefined;
  return {
    status: res.status,
    data: isObject(envelope.data) ? envelope.data : {},
    errorCode: typeof error?.code === "string" ? error.code : undefined,
    errorMessage: typeof error?.message === "string" ? error.message : undefined,
  };
}

// ---------------------------------------------------------------------------
// Manual JWT verification
// ---------------------------------------------------------------------------

/** An RSA public key as published in the JWKS (RFC 7517). */
interface Jwk {
  kty?: string;
  kid?: string;
  use?: string;
  alg?: string;
  n?: string;
  e?: string;
}

interface Claims extends Json {
  iss?: unknown;
  sub?: unknown;
  aud?: unknown;
  exp?: unknown;
  nbf?: unknown;
}

class TokenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TokenError";
  }
}

/** Keyora's public keys by key ID. Fetched once and reused. */
const keyCache = new Map<string, KeyObject>();

async function loadKeys(): Promise<void> {
  console.log("  > GET /.well-known/jwks.json");
  let res: Response;
  try {
    res = await fetch(`${KEYORA_URL}/.well-known/jwks.json`, { signal: AbortSignal.timeout(10_000) });
  } catch (cause) {
    throw new Error(`Keyora is not reachable at ${KEYORA_URL} (GET /.well-known/jwks.json)`, { cause });
  }
  if (!res.ok) throw new Error(`could not fetch the JWKS: status ${res.status}`);
  const jwks: unknown = await res.json();
  const keys = isObject(jwks) && Array.isArray(jwks.keys) ? (jwks.keys as Jwk[]) : [];
  keyCache.clear();
  for (const jwk of keys) {
    // Only RSA signing keys are of interest.
    if (!isObject(jwk) || jwk.kty !== "RSA" || typeof jwk.kid !== "string") continue;
    if (jwk.use !== undefined && jwk.use !== "sig") continue;
    keyCache.set(jwk.kid, createPublicKey({ key: jwk, format: "jwk" }));
  }
  console.log(`  < ${res.status} ${keyCache.size} RSA key(s): ${[...keyCache.keys()].map((k) => `kid=${k}`).join(", ")}`);
}

/**
 * Returns the public key for a key ID. An unknown `kid` triggers one refetch,
 * because Keyora may have rotated its signing key since the last fetch.
 */
async function publicKey(kid: string): Promise<KeyObject> {
  let key = keyCache.get(kid);
  if (!key) {
    await loadKeys();
    key = keyCache.get(kid);
  }
  if (!key) throw new TokenError(`no key with kid "${kid}" in the JWKS`);
  return key;
}

const BASE64URL = /^[A-Za-z0-9_-]+$/;

function decodeSegment(segment: string, name: string): Json {
  if (!BASE64URL.test(segment)) throw new TokenError(`the ${name} is not base64url`);
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
  } catch {
    throw new TokenError(`the ${name} is not JSON`);
  }
  if (!isObject(parsed)) throw new TokenError(`the ${name} is not a JSON object`);
  return parsed;
}

/**
 * Verifies an access token and returns its claims. All five checks are
 * required; leaving any of them out makes the result untrustworthy.
 */
async function verifyAccessToken(token: string, now: number = Math.floor(Date.now() / 1000)): Promise<Claims> {
  const parts = token.split(".");
  if (parts.length !== 3) throw new TokenError("not a JWT: expected three dot-separated parts");
  const [headerB64, payloadB64, signatureB64] = parts as [string, string, string];
  const header = decodeSegment(headerB64, "header");

  // 1. The algorithm is pinned to RS256. The header is attacker-controlled:
  //    accepting whatever it names allows "none" and HMAC-with-the-public-key
  //    forgeries.
  if (header.alg !== "RS256") throw new TokenError(`unexpected algorithm ${JSON.stringify(header.alg)}, only RS256 is accepted`);
  if (typeof header.kid !== "string" || header.kid === "") throw new TokenError("the header has no kid");

  // 2. The signature (RSASSA-PKCS1-v1_5 with SHA-256) over "<header>.<payload>"
  //    verifies against the JWKS key whose kid matches.
  if (!BASE64URL.test(signatureB64)) throw new TokenError("the signature is not base64url");
  const key = await publicKey(header.kid);
  const signed = Buffer.from(`${headerB64}.${payloadB64}`, "ascii");
  const signature = Buffer.from(signatureB64, "base64url");
  const valid = verifySignature("sha256", signed, { key, padding: constants.RSA_PKCS1_PADDING }, signature);
  if (!valid) throw new TokenError("the signature does not verify");

  // Only now is the payload trustworthy enough to read.
  const claims: Claims = decodeSegment(payloadB64, "payload");

  // 3. exp is in the future (and nbf, when present, is not).
  if (typeof claims.exp !== "number") throw new TokenError("the token has no exp claim");
  if (claims.exp <= now) throw new TokenError(`the token expired ${now - claims.exp}s ago`);
  if (claims.nbf !== undefined && (typeof claims.nbf !== "number" || claims.nbf > now)) {
    throw new TokenError("the token is not valid yet (nbf)");
  }

  // 4. iss is this Keyora.
  if (claims.iss !== ISSUER) throw new TokenError(`unexpected issuer ${JSON.stringify(claims.iss)}, want "${ISSUER}"`);

  // 5. aud is this application. Without this check a token issued to any
  //    other application on the same Keyora would be accepted here.
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audiences.includes(CLIENT_ID)) throw new TokenError(`unexpected audience ${JSON.stringify(claims.aud)}, want "${CLIENT_ID}"`);

  return claims;
}

// ---------------------------------------------------------------------------
// Walkthrough helpers
// ---------------------------------------------------------------------------

class UnexpectedResult extends Error {}

let stepNumber = 0;
function step(title: string): void {
  stepNumber += 1;
  console.log(`\n${stepNumber}. ${title}`);
}

function note(text: string): void {
  console.log(`  ${text}`);
}

/** Stops the walkthrough when a step did not go as documented. */
function expect(condition: boolean, what: string): void {
  if (!condition) throw new UnexpectedResult(what);
  console.log(`  ok: ${what}`);
}

function expectStatus(res: ApiResponse, status: number, errorCode?: string): void {
  const want = errorCode ? `${status} ${errorCode}` : `${status}`;
  const got = res.errorCode ? `${res.status} ${res.errorCode}` : `${res.status}`;
  if (res.status !== status || (errorCode !== undefined && res.errorCode !== errorCode)) {
    throw new UnexpectedResult(`expected Keyora to answer ${want}, got ${got}`);
  }
  console.log(`  ok: Keyora answered ${got}`);
}

function str(data: Json, field: string): string {
  const value = data[field];
  if (typeof value !== "string" || value === "") throw new UnexpectedResult(`the response has no "${field}"`);
  return value;
}

/** Expects local verification to refuse the token and prints the reason. */
async function expectRejected(token: string, what: string): Promise<void> {
  try {
    await verifyAccessToken(token);
  } catch (err) {
    if (err instanceof TokenError) {
      console.log(`  ok: ${what} is rejected locally: ${err.message}`);
      return;
    }
    throw err;
  }
  throw new UnexpectedResult(`${what} was accepted by local verification`);
}

function encodeSegment(value: Json): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

// ---------------------------------------------------------------------------
// The walkthrough
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  if (!CLIENT_ID || !CLIENT_SECRET) {
    throw new Error("KEYORA_CLIENT_ID and KEYORA_CLIENT_SECRET are required. Run examples/setup.sh, then: set -a; . examples/.env; set +a");
  }
  console.log(`Keyora at ${KEYORA_URL} (issuer ${ISSUER}), application ${CLIENT_ID}`);

  const app: Credentials = { basic: true };
  const email = `walkthrough-${randomBytes(6).toString("hex")}@example.com`;
  const password = randomBytes(18).toString("base64url");

  step("Register a user");
  note("The application authenticates with its client_id and client_secret (HTTP Basic).");
  const registered = await keyora("POST", "/api/v1/auth/register", { email, password, name: "Walkthrough User" }, app);
  expectStatus(registered, 201);
  const userId = str(registered.data, "id");

  step("Log in");
  const login = await keyora("POST", "/api/v1/auth/login", { email, password }, app);
  expectStatus(login, 200);
  const accessToken = str(login.data, "access_token");
  const firstRefreshToken = str(login.data, "refresh_token");
  note(`The access token is an RS256 JWT valid for ${String(login.data.expires_in)}s; the refresh token is opaque and single-use.`);

  step("Verify the access token locally");
  note("Checks: alg is RS256, signature against the JWKS key named by kid, exp, iss, aud.");
  const claims = await verifyAccessToken(accessToken);
  console.log("  claims: " + JSON.stringify(claims, null, 2).replace(/\n/g, "\n  "));
  expect(claims.sub === userId, "sub is the ID of the user registered in step 1");
  expect(claims.email === email, "email is the address that logged in");
  await verifyAccessToken(accessToken);
  note("A second verification used the cached key: no request to Keyora was made.");

  step("Call a protected Keyora endpoint with the access token");
  const me = await keyora("GET", "/api/v1/users/me", undefined, { bearer: accessToken });
  expectStatus(me, 200);
  expect(me.data.id === userId && me.data.email === email, "Keyora returns the profile of the token's user");

  step("Tampered tokens are rejected locally");
  const [headerB64, payloadB64, signatureB64] = accessToken.split(".") as [string, string, string];
  note("a) Payload edited to add an admin role, original signature kept:");
  const forgedPayload = encodeSegment({ ...claims, roles: ["admin"] });
  await expectRejected(`${headerB64}.${forgedPayload}.${signatureB64}`, "the edited token");
  note('b) Header changed to "alg":"none" and the signature removed:');
  const noneHeader = encodeSegment({ alg: "none", typ: "JWT" });
  await expectRejected(`${noneHeader}.${forgedPayload}.`, "the unsigned token");
  note("c) One character of the signature changed:");
  const flipped = signatureB64[10] === "A" ? "B" : "A";
  await expectRejected(`${headerB64}.${payloadB64}.${signatureB64.slice(0, 10)}${flipped}${signatureB64.slice(11)}`, "the token with a damaged signature");
  note("d) The genuine token, checked as if the clock were two hours ahead:");
  try {
    await verifyAccessToken(accessToken, Math.floor(Date.now() / 1000) + 7200);
    throw new UnexpectedResult("an expired token was accepted");
  } catch (err) {
    if (!(err instanceof TokenError)) throw err;
    console.log(`  ok: the expired token is rejected locally: ${err.message}`);
  }

  step("Refresh (token rotation)");
  const refreshed = await keyora("POST", "/api/v1/auth/refresh", { refresh_token: firstRefreshToken }, app);
  expectStatus(refreshed, 200);
  const secondAccessToken = str(refreshed.data, "access_token");
  const secondRefreshToken = str(refreshed.data, "refresh_token");
  expect(secondRefreshToken !== firstRefreshToken, "a new refresh token was issued; the old one is now spent");
  await verifyAccessToken(secondAccessToken);
  expect(true, "the new access token verifies locally");

  step("Replay the old refresh token");
  note("A refresh token works once. Seeing it a second time means two parties hold it,");
  note("so Keyora treats it as stolen and revokes the whole session.");
  const replay = await keyora("POST", "/api/v1/auth/refresh", { refresh_token: firstRefreshToken }, app);
  expectStatus(replay, 401, "refresh_token_reused");
  note("The session is revoked: the refresh token issued in step 6 no longer works either.");
  const afterReuse = await keyora("POST", "/api/v1/auth/refresh", { refresh_token: secondRefreshToken }, app);
  expectStatus(afterReuse, 401);
  note("The user has to log in again. Never retry a refresh with the same token.");

  step("Log in again");
  const secondLogin = await keyora("POST", "/api/v1/auth/login", { email, password }, app);
  expectStatus(secondLogin, 200);
  const sessionAccessToken = str(secondLogin.data, "access_token");
  const sessionRefreshToken = str(secondLogin.data, "refresh_token");
  const before = await keyora("POST", "/api/v1/auth/introspect", { token: sessionAccessToken }, app);
  expectStatus(before, 200);
  expect(before.data.active === true, "introspection reports active:true while the session is open");

  step("Log out");
  const logout = await keyora("POST", "/api/v1/auth/logout", { refresh_token: sessionRefreshToken }, app);
  expectStatus(logout, 204);

  step("Introspection sees the logout; local verification does not");
  const after = await keyora("POST", "/api/v1/auth/introspect", { token: sessionAccessToken }, app);
  expectStatus(after, 200);
  expect(after.data.active === false, "introspection reports active:false for the logged-out token");
  await verifyAccessToken(sessionAccessToken);
  expect(true, "the same token still verifies locally, and will until it expires");
  note("Local verification only proves the token was issued and has not expired. Keep");
  note("access tokens short-lived, and introspect before operations that must not run");
  note("on a revoked session.");

  step("Handle an invalid token");
  const garbage = "this-is-not-a-token";
  await expectRejected(garbage, "a garbage token");
  const garbageIntrospection = await keyora("POST", "/api/v1/auth/introspect", { token: garbage }, app);
  expectStatus(garbageIntrospection, 200);
  expect(garbageIntrospection.data.active === false, "introspection answers 200 with active:false, not an error");
  const garbageCall = await keyora("GET", "/api/v1/users/me", undefined, { bearer: garbage });
  expectStatus(garbageCall, 401, "invalid_token");

  console.log(`\nAll ${stepNumber} steps behaved as expected.`);
}

main().catch((err: unknown) => {
  if (err instanceof UnexpectedResult) {
    console.error(`\nFAILED at step ${stepNumber}: ${err.message}`);
  } else if (err instanceof Error) {
    console.error(`\nERROR${stepNumber ? ` at step ${stepNumber}` : ""}: ${err.message}`);
    if (err.cause instanceof Error) console.error(`  caused by: ${err.cause.message}`);
  } else {
    console.error(err);
  }
  process.exitCode = 1;
});
