<?php

declare(strict_types=1);

/**
 * Thrown when an access token is rejected. $errorCode is the contract error
 * code: "invalid_token" or "token_expired".
 */
final class TokenException extends RuntimeException
{
    public function __construct(public readonly string $errorCode, string $message)
    {
        parent::__construct($message);
    }
}

/**
 * Verifies Keyora access tokens (RS256 JWTs) with the openssl extension only.
 *
 * All six checks are required: pinned algorithm, signature against the JWKS
 * key named by "kid", expiry, issuer, audience and token use.
 */
final class Jwt
{
    /** Seconds of clock difference tolerated between this server and Keyora. */
    private const LEEWAY = 0;

    public function __construct(
        private readonly Jwks $jwks,
        private readonly string $issuer,
        private readonly string $audience,
    ) {
    }

    /**
     * @return array<string, mixed> the verified claims
     * @throws TokenException when the token must not be trusted
     * @throws RuntimeException when the JWKS cannot be loaded
     */
    public function verify(string $token): array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new TokenException('invalid_token', 'the access token is malformed');
        }
        [$headerB64, $payloadB64, $signatureB64] = $parts;

        $header = self::decodeJsonSegment($headerB64);
        $signature = self::base64UrlDecode($signatureB64);
        if ($header === null || $signature === null) {
            throw new TokenException('invalid_token', 'the access token is malformed');
        }

        // 1. Algorithm. Pinned: the token does not get to choose. This is what
        //    rules out "none" and HMAC-with-the-public-key attacks.
        if (($header['alg'] ?? null) !== 'RS256') {
            throw new TokenException('invalid_token', 'the access token uses an unsupported algorithm');
        }
        $kid = $header['kid'] ?? null;
        if (!is_string($kid) || $kid === '') {
            throw new TokenException('invalid_token', 'the access token names no signing key');
        }

        // 2. Signature, over the exact bytes received, against the key whose kid matches.
        $jwk = $this->jwks->find($kid);
        if ($jwk === null) {
            throw new TokenException('invalid_token', 'the access token was signed with an unknown key');
        }
        $publicKey = openssl_pkey_get_public(self::jwkToPem($jwk));
        if ($publicKey === false) {
            throw new RuntimeException('the JWKS contains a key that openssl cannot load');
        }
        // openssl_verify returns 1 (valid), 0 (invalid) or -1/false (error).
        // Only 1 is acceptable; a loose check would treat -1 as success.
        $ok = openssl_verify($headerB64 . '.' . $payloadB64, $signature, $publicKey, OPENSSL_ALGO_SHA256);
        if ($ok !== 1) {
            throw new TokenException('invalid_token', 'the access token signature is invalid');
        }

        // Only now is the payload trustworthy enough to read.
        $claims = self::decodeJsonSegment($payloadB64);
        if ($claims === null) {
            throw new TokenException('invalid_token', 'the access token is malformed');
        }
        $now = time();

        // 3. Expiry. A token without "exp" is refused rather than treated as eternal.
        $exp = $claims['exp'] ?? null;
        if (!is_int($exp) && !is_float($exp)) {
            throw new TokenException('invalid_token', 'the access token has no expiry');
        }
        if ($now >= $exp + self::LEEWAY) {
            throw new TokenException('token_expired', 'the access token has expired');
        }
        $nbf = $claims['nbf'] ?? null;
        if ($nbf !== null && (!(is_int($nbf) || is_float($nbf)) || $now + self::LEEWAY < $nbf)) {
            throw new TokenException('invalid_token', 'the access token is not valid yet');
        }

        // 4. Issuer: the token came from our Keyora.
        if (($claims['iss'] ?? null) !== $this->issuer) {
            throw new TokenException('invalid_token', 'the access token has the wrong issuer');
        }

        // 5. Audience: the token was issued to this application, not to
        //    another one on the same Keyora. "aud" may be a string or a list.
        $aud = $claims['aud'] ?? null;
        $audiences = is_array($aud) ? $aud : [$aud];
        if (!in_array($this->audience, $audiences, true)) {
            throw new TokenException('invalid_token', 'the access token was issued to another application');
        }

        // 6. Token use: an OIDC ID token has the same issuer and audience as an
        //    access token, so only this claim keeps it from being used as one.
        if (($claims['token_use'] ?? null) !== 'access') {
            throw new TokenException('invalid_token', 'the token is not an access token');
        }

        return $claims;
    }

    /**
     * Strict base64url decoding (RFC 7515): only the URL-safe alphabet, no
     * padding, no whitespace. Returns null for anything else.
     */
    public static function base64UrlDecode(string $input): ?string
    {
        if ($input === '' || preg_match('/\A[A-Za-z0-9_-]+\z/', $input) !== 1 || strlen($input) % 4 === 1) {
            return null;
        }
        $padded = strtr($input, '-_', '+/') . str_repeat('=', (4 - strlen($input) % 4) % 4);
        $decoded = base64_decode($padded, true);
        return $decoded === false ? null : $decoded;
    }

    /** @return array<string, mixed>|null a JSON object, or null */
    private static function decodeJsonSegment(string $segment): ?array
    {
        $raw = self::base64UrlDecode($segment);
        if ($raw === null) {
            return null;
        }
        $value = json_decode($raw, true, 16);
        // A JSON list would also decode to a PHP array; a JWT segment must be an object.
        return is_array($value) && !array_is_list($value) ? $value : null;
    }

    /**
     * Builds a PEM public key from an RSA JWK ("n" and "e" are base64url,
     * big-endian, unsigned).
     *
     *   SubjectPublicKeyInfo ::= SEQUENCE {
     *       algorithm        SEQUENCE { OID rsaEncryption, NULL },
     *       subjectPublicKey BIT STRING { RSAPublicKey }
     *   }
     *   RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
     *
     * @param array<string, mixed> $jwk
     */
    public static function jwkToPem(array $jwk): string
    {
        $n = is_string($jwk['n'] ?? null) ? self::base64UrlDecode($jwk['n']) : null;
        $e = is_string($jwk['e'] ?? null) ? self::base64UrlDecode($jwk['e']) : null;
        if (($jwk['kty'] ?? null) !== 'RSA' || $n === null || $e === null) {
            throw new RuntimeException('the JWKS contains a malformed RSA key');
        }

        $rsaPublicKey = self::derSequence(self::derUnsignedInteger($n) . self::derUnsignedInteger($e));
        // OID 1.2.840.113549.1.1.1 (rsaEncryption) followed by NULL parameters.
        $algorithm = self::derSequence("\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01" . "\x05\x00");
        // BIT STRING: the first content byte is the number of unused bits (0).
        $subjectPublicKey = "\x03" . self::derLength(strlen($rsaPublicKey) + 1) . "\x00" . $rsaPublicKey;
        $der = self::derSequence($algorithm . $subjectPublicKey);

        return "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($der), 64, "\n")
            . "-----END PUBLIC KEY-----\n";
    }

    private static function derSequence(string $content): string
    {
        return "\x30" . self::derLength(strlen($content)) . $content;
    }

    /**
     * DER INTEGER for an unsigned big-endian number. DER integers are signed
     * and minimal: redundant leading zero bytes are removed, then a single
     * zero byte is put back if the top bit is set, so the value is not read
     * as negative. A 2048-bit modulus always needs that byte.
     */
    private static function derUnsignedInteger(string $bytes): string
    {
        $bytes = ltrim($bytes, "\x00");
        if ($bytes === '') {
            $bytes = "\x00";
        }
        if ((ord($bytes[0]) & 0x80) !== 0) {
            $bytes = "\x00" . $bytes;
        }
        return "\x02" . self::derLength(strlen($bytes)) . $bytes;
    }

    /**
     * DER length: one byte below 128, otherwise 0x80|count followed by the
     * length in that many big-endian bytes.
     */
    private static function derLength(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }
        $bytes = ltrim(pack('N', $length), "\x00");
        return chr(0x80 | strlen($bytes)) . $bytes;
    }
}
