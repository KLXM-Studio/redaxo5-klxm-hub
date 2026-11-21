<?php

namespace Klxm\Hub\Monitoring;

use Klxm\Hub\Oidc\Jwk;

/**
 * Signierte Status-Abfrage, Protokoll „status-v1“ (systemneutral, gleich wie in KLXM Studio `Core\Monitoring\Signature`).
 * Ed25519 (libsodium); die Website kennt nur öffentliche Schlüssel des Hubs.
 *
 * Kopfzeilen der Anfrage:
 *   X-Status-Key        Schlüssel-ID: erste 16 Zeichen von base64url(SHA-256(öffentlicher Schlüssel))
 *   X-Status-Timestamp  Unix-Zeit in Sekunden (±300 s)
 *   X-Status-Nonce      16–64 Zeichen [A-Za-z0-9_-], je Schlüssel nur einmal in 10 Minuten
 *   X-Status-Signature  base64url(Ed25519-Signatur über die Basiszeichenkette)
 * Basiszeichenkette (Zeilen mit \n, ohne abschließenden Zeilenumbruch):
 *   status-v1 · GET · Host in Kleinbuchstaben (mit Port, wenn nicht 80/443) · Pfad mit Query · Zeitstempel · Nonce
 */
final class Signature
{
    public const string PROTOCOL = 'status-v1';
    public const int SKEW = 300;
    public const int NONCE_TTL = 600;
    /**
     * So lange merkt sich die Website einen Nonce tatsächlich: länger als das ganze Zeitfenster (2 × SKEW = NONCE_TTL)
     * plus Rand für Sekundengrenzen – sonst ließe sich eine Anfrage mit Zeitstempel +300 s genau an der Grenze
     * (gemerkt bei t, wiederholt bei t + 600) noch einmal abspielen.
     */
    public const int NONCE_KEEP = 2 * self::SKEW + 60;
    public const int MAX_KEYS = 10;

    public static function base(string $method, string $host, string $pathQuery, int $ts, string $nonce): string
    {
        return implode("\n", [self::PROTOCOL, strtoupper($method), strtolower($host), $pathQuery, (string) $ts, $nonce]);
    }

    public static function keyId(string $public): string
    {
        return substr(Jwk::b64u(hash('sha256', $public, true)), 0, 16);
    }

    /** „ed25519:…“ → 32 Byte oder null */
    public static function parseKey(string $s): ?string
    {
        if (!preg_match('~^ed25519:([A-Za-z0-9_-]{43})$~', trim($s), $m)) {
            return null;
        }
        $raw = Jwk::unb64u($m[1]);

        return false !== $raw && SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES === \strlen($raw) ? $raw : null;
    }

    public static function formatKey(string $public): string
    {
        return 'ed25519:' . Jwk::b64u($public);
    }

    /**
     * Kopfzeilen für eine Abfrage (Seite des Hubs – hier nur für Selbsttest und Werkzeuge).
     *
     * @return array<string, string>
     */
    public static function headers(string $secret, string $host, string $pathQuery, ?int $ts = null, ?string $nonce = null): array
    {
        $ts ??= time();
        $nonce ??= Jwk::b64u(random_bytes(18));
        $sig = sodium_crypto_sign_detached(self::base('GET', $host, $pathQuery, $ts, $nonce), $secret);

        return ['x-status-key' => self::keyId(sodium_crypto_sign_publickey_from_secretkey($secret)), 'x-status-timestamp' => (string) $ts,
            'x-status-nonce' => $nonce, 'x-status-signature' => Jwk::b64u($sig)];
    }

    /**
     * Anfrage prüfen (Seite der Website). $h: Kopfzeilen in Kleinbuchstaben; $keys: öffentliche Schlüssel (32 Byte);
     * $seen: fn(string $kid, string $nonce): bool – true = schon verwendet (merkt sich den Nonce sonst).
     *
     * @param array<string, string> $h
     * @param list<string> $keys
     * @param callable(string, string): bool $seen
     * @return string|null Fehlergrund (format, time, key, signature, replay) oder null (gültig)
     */
    public static function verify(array $h, string $method, string $host, string $pathQuery, array $keys, callable $seen, ?int $now = null): ?string
    {
        $now ??= time();
        $kid = (string) ($h['x-status-key'] ?? '');
        $ts = (string) ($h['x-status-timestamp'] ?? '');
        $nonce = (string) ($h['x-status-nonce'] ?? '');
        $sig = Jwk::unb64u((string) ($h['x-status-signature'] ?? ''));
        if (!preg_match('~^[A-Za-z0-9_-]{16}$~', $kid) || !preg_match('~^\d{9,11}$~', $ts) || !preg_match('~^[A-Za-z0-9_-]{16,64}$~', $nonce)
            || false === $sig || SODIUM_CRYPTO_SIGN_BYTES !== \strlen($sig)) {
            return 'format';
        }
        if (abs($now - (int) $ts) > self::SKEW) {
            return 'time';
        }
        $pub = null;
        foreach ($keys as $k) {
            if (SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES === \strlen($k) && hash_equals(self::keyId($k), $kid)) {
                $pub = $k;
                break;
            }
        }
        if (null === $pub) {
            return 'key';
        }
        if (!sodium_crypto_sign_verify_detached($sig, self::base($method, $host, $pathQuery, (int) $ts, $nonce), $pub)) {
            return 'signature';
        }
        // Erst nach gültiger Signatur merken – sonst könnten Fremde Nonces „verbrauchen“
        if ($seen($kid, $nonce)) {
            return 'replay';
        }

        return null;
    }
}
