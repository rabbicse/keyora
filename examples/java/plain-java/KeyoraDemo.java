import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * A walkthrough of the Keyora authentication flow using only the JDK.
 *
 *     java KeyoraDemo.java
 *
 * It registers a user, signs in, verifies the access token by hand, refreshes, shows what
 * happens when a refresh token is replayed, logs out, and checks the result by
 * introspection. Each step prints what it sent and what came back. The exit code is 0
 * when every step behaved as expected and 1 otherwise.
 *
 * Configuration comes from the environment: KEYORA_URL, KEYORA_ISSUER, KEYORA_CLIENT_ID,
 * KEYORA_CLIENT_SECRET (see README.md).
 *
 * The file has three parts: the walkthrough (main), JWT verification (verifyAccessToken),
 * and a minimal JSON reader and writer (class Json), because the JDK has none.
 */
public class KeyoraDemo {

    static final String KEYORA_URL = env("KEYORA_URL", "http://localhost:8080").replaceAll("/+$", "");
    static final String ISSUER = env("KEYORA_ISSUER", KEYORA_URL);
    static final String CLIENT_ID = env("KEYORA_CLIENT_ID", "");
    static final String CLIENT_SECRET = env("KEYORA_CLIENT_SECRET", "");

    static final HttpClient HTTP = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    static int failures = 0;

    public static void main(String[] args) {
        if (CLIENT_ID.isEmpty() || CLIENT_SECRET.isEmpty()) {
            System.err.println("KEYORA_CLIENT_ID and KEYORA_CLIENT_SECRET are required.");
            System.err.println("Run examples/setup.sh, then: set -a; . examples/.env; set +a");
            System.exit(2);
        }
        try {
            walkthrough();
        } catch (Exception e) {
            failures++;
            System.out.println("\n  FAIL  stopped by an unexpected error: " + e);
        }
        System.out.println();
        if (failures == 0) {
            System.out.println("All steps behaved as expected.");
        } else {
            System.out.println(failures + " step(s) did not behave as expected.");
            System.exit(1);
        }
    }

    static void walkthrough() throws Exception {
        System.out.println("Keyora at " + KEYORA_URL + ", issuer " + ISSUER + ", application " + CLIENT_ID);

        String email = "demo-" + UUID.randomUUID().toString().substring(0, 12) + "@example.com";
        String password = "correct horse battery staple";
        Map<String, Object> credentials = Json.object("email", email, "password", password);

        // The application authenticates to Keyora with its client ID and secret (HTTP Basic).
        // This is a server-side credential: never put it in a browser or mobile app.
        String app = "Basic " + Base64.getEncoder()
                .encodeToString((CLIENT_ID + ":" + CLIENT_SECRET).getBytes(StandardCharsets.UTF_8));

        step(1, "Register a user");
        Response res = post("/api/v1/auth/register", app,
                Json.object("email", email, "password", password, "name", "Demo User"));
        check(res.status == 201, "201 Created", res);
        Map<String, Object> user = res.data();
        String userId = Json.string(user, "id");
        System.out.println("  user id: " + userId + ", email: " + Json.string(user, "email"));

        step(2, "Log in with email and password");
        res = post("/api/v1/auth/login", app, credentials);
        check(res.status == 200, "200 OK", res);
        String accessToken = Json.string(res.data(), "access_token");
        String refreshToken = Json.string(res.data(), "refresh_token");
        System.out.println("  access_token:  " + shorten(accessToken) + "  (RS256 JWT, expires in "
                + res.data().get("expires_in") + "s)");
        System.out.println("  refresh_token: " + shorten(refreshToken) + "  (opaque, single use)");

        step(3, "Verify the access token locally (no call to Keyora except fetching the JWKS once)");
        Map<String, Object> claims = verifyAccessToken(accessToken);
        System.out.println("  signature, exp, iss and aud are all valid. Claims:");
        for (String name : List.of("iss", "aud", "sub", "email", "roles", "permissions", "exp")) {
            System.out.println("    " + pad(name) + Json.write(claims.get(name)));
        }
        System.out.println("  (roles and permissions are null until an administrator assigns the user a role)");
        check(userId.equals(claims.get("sub")), "sub is the id of the user registered in step 1", null);

        step(4, "Call a Keyora endpoint protected by the access token: GET /api/v1/users/me");
        res = get("/api/v1/users/me", "Bearer " + accessToken);
        check(res.status == 200 && email.equals(Json.string(res.data(), "email")), "200 OK with our profile", res);
        System.out.println("  profile: email=" + Json.string(res.data(), "email")
                + " roles=" + Json.write(res.data().get("roles"))
                + " permissions=" + Json.write(res.data().get("permissions")));

        step(5, "A tampered token is rejected locally");
        expectRejected(tamperSignature(accessToken), "one character of the signature changed", "invalid_signature");
        expectRejected(forgeAdminPayload(accessToken), "payload edited to add an \"admin\" role", "invalid_signature");

        step(6, "Refresh: exchange the refresh token for new tokens (rotation)");
        res = post("/api/v1/auth/refresh", app, Json.object("refresh_token", refreshToken));
        check(res.status == 200, "200 OK", res);
        String oldRefreshToken = refreshToken;
        accessToken = Json.string(res.data(), "access_token");
        refreshToken = Json.string(res.data(), "refresh_token");
        check(!refreshToken.equals(oldRefreshToken), "the refresh token changed: the old one is now spent", null);
        verifyAccessToken(accessToken);
        System.out.println("  new access_token verifies locally: " + shorten(accessToken));

        step(7, "Replay the OLD refresh token");
        res = post("/api/v1/auth/refresh", app, Json.object("refresh_token", oldRefreshToken));
        check(res.status == 401 && "refresh_token_reused".equals(res.errorCode()), "401 refresh_token_reused", res);
        System.out.println("  A refresh token works once. Keyora cannot tell whether the second use came from");
        System.out.println("  the real client or from someone who stole the token, so it treats it as theft");
        System.out.println("  and revokes the whole session, including the tokens issued in step 6:");
        res = post("/api/v1/auth/refresh", app, Json.object("refresh_token", refreshToken));
        check(res.status == 401, "the NEW refresh token from step 6 is refused too (401)", res);
        res = post("/api/v1/auth/introspect", app, Json.object("token", accessToken));
        check(res.status == 200 && Boolean.FALSE.equals(res.data().get("active")),
                "introspection reports the step 6 access token as active=false", res);
        System.out.println("  The user has to log in again. So: store the new refresh token before using the");
        System.out.println("  new access token, and never retry a refresh with a token you already sent.");

        step(8, "Log in again");
        res = post("/api/v1/auth/login", app, credentials);
        check(res.status == 200, "200 OK", res);
        accessToken = Json.string(res.data(), "access_token");
        refreshToken = Json.string(res.data(), "refresh_token");
        res = post("/api/v1/auth/introspect", app, Json.object("token", accessToken));
        check(res.status == 200 && Boolean.TRUE.equals(res.data().get("active")),
                "introspection reports the new access token as active=true", res);

        step(9, "Log out (revokes the session)");
        res = post("/api/v1/auth/logout", app, Json.object("refresh_token", refreshToken));
        check(res.status == 204, "204 No Content", res);

        step(10, "After logout: introspection against local verification");
        res = post("/api/v1/auth/introspect", app, Json.object("token", accessToken));
        check(res.status == 200 && Boolean.FALSE.equals(res.data().get("active")),
                "introspection reports active=false", res);
        Map<String, Object> stillValid = verifyAccessToken(accessToken);
        long secondsLeft = ((Number) stillValid.get("exp")).longValue() - Instant.now().getEpochSecond();
        System.out.println("  ok    local verification still accepts the token for another " + secondsLeft + "s:");
        System.out.println("        a signed token cannot be recalled. Keep access tokens short-lived and use");
        System.out.println("        introspection where acting on a revoked session would be unacceptable.");

        step(11, "A garbage token is rejected");
        expectRejected("not-a-token", "local verification of \"not-a-token\"", "malformed_token");
        res = post("/api/v1/auth/introspect", app, Json.object("token", "not-a-token"));
        check(res.status == 200 && Boolean.FALSE.equals(res.data().get("active")),
                "introspection reports active=false", res);
        res = get("/api/v1/users/me", "Bearer not-a-token");
        check(res.status == 401, "GET /api/v1/users/me answers 401", res);
    }

    // ------------------------------------------------------------------------------------
    // JWT verification
    // ------------------------------------------------------------------------------------

    /** Why a token was refused. The code is for this program's output only. */
    static class TokenRejected extends Exception {
        final String code;

        TokenRejected(String code, String message) {
            super(message);
            this.code = code;
        }
    }

    /** Keyora's public keys by key ID, fetched on first use. */
    static Map<String, RSAPublicKey> jwks = Map.of();

    /**
     * Verifies an access token and returns its claims. All five checks are required;
     * leaving any one out makes the others worthless.
     */
    static Map<String, Object> verifyAccessToken(String token) throws Exception {
        // A JWT is three base64url parts: header.payload.signature
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3) {
            throw new TokenRejected("malformed_token", "expected three dot-separated parts, found " + parts.length);
        }
        Map<String, Object> header;
        Map<String, Object> claims;
        byte[] signature;
        try {
            header = Json.asObject(Json.parse(new String(base64Url(parts[0]), StandardCharsets.UTF_8)));
            claims = Json.asObject(Json.parse(new String(base64Url(parts[1]), StandardCharsets.UTF_8)));
            signature = base64Url(parts[2]);
        } catch (IllegalArgumentException e) { // bad base64, bad JSON, or not a JSON object
            throw new TokenRejected("malformed_token", "the token cannot be decoded: " + e.getMessage());
        }

        // 1. The algorithm is pinned. The header is attacker-controlled input: a verifier that
        //    used whatever algorithm it names could be talked into "none" or into HMAC with
        //    the public key as the secret.
        if (!"RS256".equals(header.get("alg"))) {
            throw new TokenRejected("unsupported_algorithm", "alg must be RS256, found " + Json.write(header.get("alg")));
        }

        // 2. The signature verifies against the JWKS key named by the header's kid. What is
        //    signed is the first two parts exactly as they appear in the token.
        if (!(header.get("kid") instanceof String kid)) {
            throw new TokenRejected("unknown_key", "the token header has no kid");
        }
        RSAPublicKey key = signingKey(kid);
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(key);
        verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
        boolean signatureValid;
        try {
            signatureValid = verifier.verify(signature);
        } catch (java.security.SignatureException e) { // for example, a signature of the wrong length
            signatureValid = false;
        }
        if (!signatureValid) {
            throw new TokenRejected("invalid_signature", "the signature does not match the token's content");
        }

        // Only now can the claims be believed.
        long now = Instant.now().getEpochSecond();

        // 3. Not expired (and, if nbf is present, already valid).
        if (!(claims.get("exp") instanceof Number exp)) {
            throw new TokenRejected("invalid_claims", "the token has no numeric exp claim");
        }
        if (now >= exp.longValue()) {
            throw new TokenRejected("token_expired", "the token expired " + (now - exp.longValue()) + "s ago");
        }
        if (claims.get("nbf") instanceof Number nbf && now < nbf.longValue()) {
            throw new TokenRejected("invalid_claims", "the token is not valid yet (nbf)");
        }

        // 4. Issued by our Keyora.
        if (!ISSUER.equals(claims.get("iss"))) {
            throw new TokenRejected("wrong_issuer",
                    "iss is " + Json.write(claims.get("iss")) + ", expected \"" + ISSUER + "\"");
        }

        // 5. Issued for this application. Without this check, a token that Keyora issued to
        //    any other application would be accepted here. aud may be a string or an array.
        Object aud = claims.get("aud");
        boolean forUs = CLIENT_ID.equals(aud) || (aud instanceof List<?> list && list.contains(CLIENT_ID));
        if (!forUs) {
            throw new TokenRejected("wrong_audience", "aud is " + Json.write(aud) + ", expected \"" + CLIENT_ID + "\"");
        }
        return claims;
    }

    /** Returns the key with this ID, fetching the JWKS again once if the ID is new (key rotation). */
    static RSAPublicKey signingKey(String kid) throws Exception {
        if (!jwks.containsKey(kid)) {
            jwks = fetchJwks();
        }
        RSAPublicKey key = jwks.get(kid);
        if (key == null) {
            throw new TokenRejected("unknown_key", "no key with kid \"" + kid + "\" in Keyora's JWKS");
        }
        return key;
    }

    /** GET /.well-known/jwks.json: {"keys":[{"kty":"RSA","kid":"...","n":"...","e":"..."}]} */
    static Map<String, RSAPublicKey> fetchJwks() throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(KEYORA_URL + "/.well-known/jwks.json"))
                .timeout(Duration.ofSeconds(10)).GET().build();
        HttpResponse<String> response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("fetching the JWKS failed with status " + response.statusCode());
        }
        Map<String, RSAPublicKey> keys = new LinkedHashMap<>();
        KeyFactory rsa = KeyFactory.getInstance("RSA");
        for (Object entry : Json.asList(Json.asObject(Json.parse(response.body())).get("keys"))) {
            Map<String, Object> jwk = Json.asObject(entry);
            if (!"RSA".equals(jwk.get("kty")) || !(jwk.get("kid") instanceof String kid)) {
                continue;
            }
            // n (modulus) and e (exponent) are unsigned big-endian integers in base64url.
            BigInteger modulus = new BigInteger(1, base64Url(Json.string(jwk, "n")));
            BigInteger exponent = new BigInteger(1, base64Url(Json.string(jwk, "e")));
            keys.put(kid, (RSAPublicKey) rsa.generatePublic(new RSAPublicKeySpec(modulus, exponent)));
        }
        System.out.println("  fetched JWKS: " + keys.size() + " key(s), kid " + keys.keySet());
        return keys;
    }

    static byte[] base64Url(String value) {
        return Base64.getUrlDecoder().decode(value);
    }

    /** Changes one character in the middle of the signature. */
    static String tamperSignature(String token) {
        int at = token.lastIndexOf('.') + 11;
        char replacement = token.charAt(at) == 'A' ? 'B' : 'A';
        return token.substring(0, at) + replacement + token.substring(at + 1);
    }

    /** Rewrites the payload to claim an extra role, keeping the original signature. */
    static String forgeAdminPayload(String token) {
        String[] parts = token.split("\\.");
        Map<String, Object> claims = Json.asObject(Json.parse(new String(base64Url(parts[1]), StandardCharsets.UTF_8)));
        claims.put("roles", List.of("admin"));
        String forged = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(Json.write(claims).getBytes(StandardCharsets.UTF_8));
        return parts[0] + "." + forged + "." + parts[2];
    }

    static void expectRejected(String token, String what, String expectedCode) throws Exception {
        try {
            verifyAccessToken(token);
            check(false, what + ": rejected", null);
            System.out.println("        the token was ACCEPTED");
        } catch (TokenRejected e) {
            check(e.code.equals(expectedCode), what + ": rejected (" + e.code + ": " + e.getMessage() + ")", null);
        }
    }

    // ------------------------------------------------------------------------------------
    // HTTP
    // ------------------------------------------------------------------------------------

    /** A Keyora response. Every /api/v1 body is an envelope: {"data": ...} or {"error": ...}, plus "meta". */
    static class Response {
        final int status;
        final Map<String, Object> envelope;

        Response(int status, String body) {
            this.status = status;
            this.envelope = body.isBlank() ? Map.of() : Json.asObject(Json.parse(body));
        }

        Map<String, Object> data() {
            if (!(envelope.get("data") instanceof Map)) {
                throw new IllegalStateException("status " + status + " has no data object: " + Json.write(envelope));
            }
            return Json.asObject(envelope.get("data"));
        }

        String errorCode() {
            return envelope.get("error") instanceof Map<?, ?> error && error.get("code") instanceof String code
                    ? code : null;
        }
    }

    static Response post(String path, String authorization, Map<String, Object> body) throws Exception {
        System.out.println("  POST " + path);
        return send(HttpRequest.newBuilder(URI.create(KEYORA_URL + path))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(Json.write(body))), authorization);
    }

    static Response get(String path, String authorization) throws Exception {
        System.out.println("  GET " + path);
        return send(HttpRequest.newBuilder(URI.create(KEYORA_URL + path)).GET(), authorization);
    }

    static Response send(HttpRequest.Builder request, String authorization) throws Exception {
        request.timeout(Duration.ofSeconds(10)).header("Accept", "application/json").header("Authorization", authorization);
        HttpResponse<String> response = HTTP.send(request.build(), HttpResponse.BodyHandlers.ofString());
        return new Response(response.statusCode(), response.body());
    }

    // ------------------------------------------------------------------------------------
    // Output helpers
    // ------------------------------------------------------------------------------------

    static void step(int number, String title) {
        System.out.println("\n" + number + ". " + title);
    }

    /** Prints the outcome of one expectation and counts it when it fails. */
    static void check(boolean ok, String expectation, Response got) {
        if (ok) {
            System.out.println("  ok    " + expectation);
            return;
        }
        failures++;
        System.out.println("  FAIL  expected: " + expectation
                + (got == null ? "" : "; got " + got.status + " " + Json.write(got.envelope)));
    }

    static String shorten(String token) {
        return token.length() <= 28 ? token : token.substring(0, 24) + "..." + " (" + token.length() + " chars)";
    }

    static String pad(String name) {
        return (name + ":              ").substring(0, 13);
    }

    static String env(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? fallback : value;
    }

    // ------------------------------------------------------------------------------------
    // Minimal JSON (RFC 8259)
    //
    // parse() turns a document into Map (object, insertion-ordered), List (array), String,
    // Long or Double (number), Boolean, or null. write() does the reverse. Malformed input
    // raises IllegalArgumentException. This is enough for Keyora's responses; a real project
    // should use a JSON library.
    // ------------------------------------------------------------------------------------

    static final class Json {
        private final String text;
        private int pos = 0;

        private Json(String text) {
            this.text = text;
        }

        static Object parse(String text) {
            Json reader = new Json(text);
            reader.skipWhitespace();
            Object value = reader.readValue(0);
            reader.skipWhitespace();
            if (reader.pos != text.length()) {
                throw reader.error("unexpected content after the JSON value");
            }
            return value;
        }

        private Object readValue(int depth) {
            if (depth > 64) {
                throw error("nesting too deep");
            }
            if (pos >= text.length()) {
                throw error("unexpected end of input");
            }
            char c = text.charAt(pos);
            switch (c) {
                case '{':
                    return readObject(depth);
                case '[':
                    return readArray(depth);
                case '"':
                    return readString();
                case 't':
                    return readLiteral("true", Boolean.TRUE);
                case 'f':
                    return readLiteral("false", Boolean.FALSE);
                case 'n':
                    return readLiteral("null", null);
                default:
                    if (c == '-' || (c >= '0' && c <= '9')) {
                        return readNumber();
                    }
                    throw error("unexpected character '" + c + "'");
            }
        }

        private Map<String, Object> readObject(int depth) {
            Map<String, Object> object = new LinkedHashMap<>();
            pos++; // {
            skipWhitespace();
            if (peek() == '}') {
                pos++;
                return object;
            }
            while (true) {
                skipWhitespace();
                if (peek() != '"') {
                    throw error("expected a string key");
                }
                String key = readString();
                skipWhitespace();
                expect(':');
                skipWhitespace();
                object.put(key, readValue(depth + 1));
                skipWhitespace();
                if (peek() == ',') {
                    pos++;
                } else {
                    expect('}');
                    return object;
                }
            }
        }

        private List<Object> readArray(int depth) {
            List<Object> array = new ArrayList<>();
            pos++; // [
            skipWhitespace();
            if (peek() == ']') {
                pos++;
                return array;
            }
            while (true) {
                skipWhitespace();
                array.add(readValue(depth + 1));
                skipWhitespace();
                if (peek() == ',') {
                    pos++;
                } else {
                    expect(']');
                    return array;
                }
            }
        }

        private String readString() {
            StringBuilder out = new StringBuilder();
            pos++; // opening quote
            while (true) {
                if (pos >= text.length()) {
                    throw error("unterminated string");
                }
                char c = text.charAt(pos++);
                if (c == '"') {
                    return out.toString();
                }
                if (c < 0x20) {
                    throw error("unescaped control character in string");
                }
                if (c != '\\') {
                    out.append(c);
                    continue;
                }
                if (pos >= text.length()) {
                    throw error("unterminated escape sequence");
                }
                char escape = text.charAt(pos++);
                switch (escape) {
                    case '"': out.append('"'); break;
                    case '\\': out.append('\\'); break;
                    case '/': out.append('/'); break;
                    case 'b': out.append('\b'); break;
                    case 'f': out.append('\f'); break;
                    case 'n': out.append('\n'); break;
                    case 'r': out.append('\r'); break;
                    case 't': out.append('\t'); break;
                    case 'u':
                        // Four hex digits giving one UTF-16 code unit. Characters outside the
                        // Basic Multilingual Plane arrive as two such escapes (a surrogate
                        // pair), which a Java String stores the same way.
                        if (pos + 4 > text.length()) {
                            throw error("incomplete \\u escape");
                        }
                        int unit = 0;
                        for (int i = 0; i < 4; i++) {
                            int digit = Character.digit(text.charAt(pos++), 16);
                            if (digit < 0) {
                                throw error("invalid \\u escape");
                            }
                            unit = unit * 16 + digit;
                        }
                        out.append((char) unit);
                        break;
                    default:
                        throw error("invalid escape '\\" + escape + "'");
                }
            }
        }

        /** number = [ "-" ] int [ "." digits ] [ ("e" / "E") [ "+" / "-" ] digits ] */
        private Number readNumber() {
            int start = pos;
            boolean integer = true;
            if (peek() == '-') {
                pos++;
            }
            if (peek() == '0') {
                pos++; // a leading zero must stand alone
            } else {
                readDigits();
            }
            if (peek() == '.') {
                integer = false;
                pos++;
                readDigits();
            }
            if (peek() == 'e' || peek() == 'E') {
                integer = false;
                pos++;
                if (peek() == '+' || peek() == '-') {
                    pos++;
                }
                readDigits();
            }
            String literal = text.substring(start, pos);
            if (integer) {
                try {
                    return Long.parseLong(literal);
                } catch (NumberFormatException tooLarge) {
                    // fall through: keep the magnitude as a double
                }
            }
            return Double.parseDouble(literal);
        }

        private void readDigits() {
            int start = pos;
            while (pos < text.length() && text.charAt(pos) >= '0' && text.charAt(pos) <= '9') {
                pos++;
            }
            if (pos == start) {
                throw error("expected a digit");
            }
        }

        private Object readLiteral(String literal, Object value) {
            if (!text.startsWith(literal, pos)) {
                throw error("expected " + literal);
            }
            pos += literal.length();
            return value;
        }

        private void skipWhitespace() {
            while (pos < text.length() && " \t\n\r".indexOf(text.charAt(pos)) >= 0) {
                pos++;
            }
        }

        /** The next character, or NUL at the end of input (NUL never matches anything expected). */
        private char peek() {
            return pos < text.length() ? text.charAt(pos) : '\0';
        }

        private void expect(char c) {
            if (peek() != c) {
                throw error("expected '" + c + "'");
            }
            pos++;
        }

        private IllegalArgumentException error(String message) {
            return new IllegalArgumentException("invalid JSON at offset " + pos + ": " + message);
        }

        // ---- typed access ----

        @SuppressWarnings("unchecked")
        static Map<String, Object> asObject(Object value) {
            if (!(value instanceof Map)) {
                throw new IllegalArgumentException("expected a JSON object, found " + write(value));
            }
            return (Map<String, Object>) value;
        }

        @SuppressWarnings("unchecked")
        static List<Object> asList(Object value) {
            if (!(value instanceof List)) {
                throw new IllegalArgumentException("expected a JSON array, found " + write(value));
            }
            return (List<Object>) value;
        }

        static String string(Map<String, Object> object, String key) {
            if (!(object.get(key) instanceof String value)) {
                throw new IllegalArgumentException("expected a string at \"" + key + "\", found " + write(object.get(key)));
            }
            return value;
        }

        // ---- writing ----

        /** Builds an object from alternating keys and values. */
        static Map<String, Object> object(Object... keysAndValues) {
            Map<String, Object> object = new LinkedHashMap<>();
            for (int i = 0; i < keysAndValues.length; i += 2) {
                object.put((String) keysAndValues[i], keysAndValues[i + 1]);
            }
            return object;
        }

        static String write(Object value) {
            StringBuilder out = new StringBuilder();
            write(value, out);
            return out.toString();
        }

        private static void write(Object value, StringBuilder out) {
            if (value == null || value instanceof Boolean || value instanceof Number) {
                out.append(value);
            } else if (value instanceof Map<?, ?> map) {
                out.append('{');
                String separator = "";
                for (Map.Entry<?, ?> entry : map.entrySet()) {
                    out.append(separator);
                    writeString(String.valueOf(entry.getKey()), out);
                    out.append(':');
                    write(entry.getValue(), out);
                    separator = ",";
                }
                out.append('}');
            } else if (value instanceof Iterable<?> items) {
                out.append('[');
                String separator = "";
                for (Object item : items) {
                    out.append(separator);
                    write(item, out);
                    separator = ",";
                }
                out.append(']');
            } else {
                writeString(value.toString(), out);
            }
        }

        private static void writeString(String value, StringBuilder out) {
            out.append('"');
            for (int i = 0; i < value.length(); i++) {
                char c = value.charAt(i);
                switch (c) {
                    case '"': out.append("\\\""); break;
                    case '\\': out.append("\\\\"); break;
                    case '\n': out.append("\\n"); break;
                    case '\r': out.append("\\r"); break;
                    case '\t': out.append("\\t"); break;
                    default:
                        if (c < 0x20) {
                            out.append(String.format("\\u%04x", (int) c));
                        } else {
                            out.append(c);
                        }
                }
            }
            out.append('"');
        }
    }
}
