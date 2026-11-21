<?php

namespace Klxm\Hub\Oidc;

/**
 * JSON Web Keys (RFC 7517) ohne Zusatzbibliothek: öffentliche RSA-Schlüssel (kty RSA, n/e → PEM für openssl).
 * Andere Schlüsselarten werden ignoriert. Dazu base64url (RFC 4648 §5) für JWT, PKCE und die Status-Signatur.
 */
final class Jwk
{
    /** Kleinste erlaubte RSA-Schlüssellänge */
    public const int RSA_MIN_BITS = 2048;

    public static function b64u(string $bin): string
    {
        return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
    }

    public static function unb64u(string $s): string|false
    {
        if ('' === $s || !preg_match('~^[A-Za-z0-9_-]+$~', $s)) {
            return false;
        }

        return base64_decode(strtr($s, '-_', '+/') . str_repeat('=', (4 - \strlen($s) % 4) % 4), true);
    }

    /**
     * RSA-JWK → PEM (SubjectPublicKeyInfo) oder null bei ungültigem/zu kurzem Schlüssel.
     *
     * @param array<mixed> $jwk
     */
    public static function rsaPem(array $jwk): ?string
    {
        if (($jwk['kty'] ?? '') !== 'RSA') {
            return null;
        }
        $n = self::unb64u((string) ($jwk['n'] ?? ''));
        $e = self::unb64u((string) ($jwk['e'] ?? ''));
        if (false === $n || false === $e) {
            return null;
        }
        $n = ltrim($n, "\0");
        $e = ltrim($e, "\0");
        // Länge auf das Bit genau (256 Byte mit führenden Null-Bits wären sonst „2048 Bit“); Exponent ungerade und ≥ 3
        $bits = '' === $n ? 0 : \strlen($n) * 8 - (8 - \strlen(decbin(\ord($n[0]))));
        if ($bits < self::RSA_MIN_BITS || '' === $e || \strlen($e) > 8 || 0 === (\ord($e[-1]) & 1) || (1 === \strlen($e) && \ord($e) < 3)) {
            return null;
        }
        $rsa = self::seq(self::int($n) . self::int($e));
        $algo = self::seq("\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01" . "\x05\x00");   // rsaEncryption, NULL
        $spki = self::seq($algo . "\x03" . self::len(\strlen($rsa) + 1) . "\0" . $rsa);

        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spki), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    /**
     * Öffentlicher RSA-Schlüssel → JWK (Selbsttest).
     *
     * @return array<string, string>
     */
    public static function fromRsa(\OpenSSLAsymmetricKey $key, string $kid): array
    {
        $d = openssl_pkey_get_details($key);
        if (!$d || ($d['type'] ?? -1) !== OPENSSL_KEYTYPE_RSA) {
            throw new \InvalidArgumentException('Kein RSA-Schlüssel.');
        }

        return ['kty' => 'RSA', 'n' => self::b64u($d['rsa']['n']), 'e' => self::b64u($d['rsa']['e']), 'kid' => $kid, 'use' => 'sig', 'alg' => 'RS256'];
    }

    // ---------------------------------------------------------------- DER

    private static function len(int $n): string
    {
        if ($n < 128) {
            return \chr($n);
        }
        $b = ltrim(pack('N', $n), "\0");

        return \chr(0x80 | \strlen($b)) . $b;
    }

    private static function seq(string $inner): string
    {
        return "\x30" . self::len(\strlen($inner)) . $inner;
    }

    private static function int(string $bytes): string
    {
        if ('' === $bytes || \ord($bytes[0]) & 0x80) {
            $bytes = "\0" . $bytes;
        }

        return "\x02" . self::len(\strlen($bytes)) . $bytes;
    }
}
