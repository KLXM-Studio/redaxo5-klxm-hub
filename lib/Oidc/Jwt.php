<?php

namespace Klxm\Hub\Oidc;

/**
 * Signierte JSON Web Tokens (JWS Compact, RFC 7515/7519) – nur RS256 (RSASSA-PKCS1-v1_5 mit SHA-256, Schlüssel ≥ 2048 Bit).
 * „none“, HS* (ein öffentlicher Schlüssel würde als HMAC-Geheimnis missbraucht) und kritische Kopf-Erweiterungen („crit“)
 * werden immer abgewiesen. Schlüssel kommen aus einem JWKS ('keys' => [...]); mit kid nur der passende Schlüssel,
 * ohne kid nur ein eindeutiger.
 */
final class Jwt
{
    public const string ALG = 'RS256';
    private const int MAX_LEN = 16384;

    /**
     * Signatur prüfen.
     *
     * @param array<mixed> $jwks
     * @throws JwtException mit Grund (unknown_kid/no_key für „Schlüssel neu laden“)
     * @return array{0: array<mixed>, 1: array<mixed>} [Kopf, Inhalt]
     */
    public static function verify(string $jwt, array $jwks): array
    {
        if (\strlen($jwt) > self::MAX_LEN) {
            throw new JwtException('too_long');
        }
        $parts = explode('.', $jwt);
        if (3 !== \count($parts)) {
            throw new JwtException('format');
        }
        [$h64, $p64, $s64] = $parts;
        $header = json_decode((string) Jwk::unb64u($h64), true);
        $payload = json_decode((string) Jwk::unb64u($p64), true);
        $sig = Jwk::unb64u($s64);
        if (!\is_array($header) || !\is_array($payload) || false === $sig) {
            throw new JwtException('format');
        }
        if (self::ALG !== ($header['alg'] ?? '')) {
            throw new JwtException('alg');
        }
        if (isset($header['crit'])) {
            throw new JwtException('crit');
        }
        if (isset($header['typ']) && !\in_array(strtolower((string) $header['typ']), ['jwt'], true)) {
            throw new JwtException('typ');
        }
        $kid = isset($header['kid']) ? (string) $header['kid'] : null;
        $cands = [];
        foreach ((array) ($jwks['keys'] ?? []) as $k) {
            if (!\is_array($k) || ($k['kty'] ?? '') !== 'RSA') {
                continue;
            }
            if (isset($k['use']) && 'sig' !== $k['use']) {
                continue;
            }
            if (isset($k['alg']) && self::ALG !== $k['alg']) {
                continue;
            }
            if (null !== $kid && (string) ($k['kid'] ?? '') !== $kid) {
                continue;
            }
            $cands[] = $k;
        }
        if (!$cands) {
            throw new JwtException(null !== $kid ? 'unknown_kid' : 'no_key');
        }
        if (null === $kid && \count($cands) > 1) {
            throw new JwtException('ambiguous_key');
        }
        foreach ($cands as $k) {
            $pem = Jwk::rsaPem($k);
            if (null !== $pem && 1 === openssl_verify($h64 . '.' . $p64, $sig, $pem, OPENSSL_ALGO_SHA256)) {
                return [$header, $payload];
            }
        }
        throw new JwtException('signature');
    }

    /**
     * Signieren (nur Selbsttest).
     *
     * @param array<mixed> $payload
     * @param array<string, mixed> $header
     */
    public static function sign(array $payload, \OpenSSLAsymmetricKey $key, ?string $kid = null, array $header = []): string
    {
        $h = $header + ['alg' => self::ALG, 'typ' => 'JWT'] + (null !== $kid ? ['kid' => $kid] : []);
        $input = Jwk::b64u((string) json_encode($h, JSON_UNESCAPED_SLASHES)) . '.' . Jwk::b64u((string) json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
        if (!openssl_sign($input, $sig, $key, OPENSSL_ALGO_SHA256)) {
            throw new \RuntimeException('Signieren fehlgeschlagen.');
        }

        return $input . '.' . Jwk::b64u((string) $sig);
    }

    /** at_hash (OIDC Core 3.1.3.6): linke Hälfte von SHA-256 */
    public static function halfHash(string $value): string
    {
        return Jwk::b64u(substr(hash('sha256', $value, true), 0, 16));
    }
}
