<?php

namespace Klxm\Hub;

use rex_file;
use rex_path;

/**
 * Verschlüsselung des Client-Geheimnisses (libsodium secretbox, XSalsa20-Poly1305).
 *
 * Der Schlüssel liegt NICHT in der Datenbank, sondern in `redaxo/data/addons/klxm_hub/secret.key` (32 Byte, nur für den
 * Webserver lesbar). Ein Datenbank-Abzug allein verrät das Geheimnis also nicht. Geht die Datei verloren, muss das
 * Geheimnis neu eingetragen werden. Alternative ohne Speicherung: Umgebungsvariable KLXM_HUB_CLIENT_SECRET.
 */
final class Secret
{
    /** Für den Selbsttest: fester Schlüssel statt der Datei */
    public static ?string $testKey = null;

    public static function encrypt(string $plain): string
    {
        if ('' === $plain) {
            return '';
        }
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

        return 'v1:' . base64_encode($nonce . sodium_crypto_secretbox($plain, $nonce, self::key(true)));
    }

    public static function decrypt(string $sealed): string
    {
        if (!str_starts_with($sealed, 'v1:')) {
            return '';
        }
        $raw = base64_decode(substr($sealed, 3), true);
        $key = self::key(false);
        if (false === $raw || null === $key || \strlen($raw) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
            return '';
        }
        $plain = sodium_crypto_secretbox_open(substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES), substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES), $key);

        return false === $plain ? '' : $plain;
    }

    /** @return ($create is true ? string : ?string) */
    private static function key(bool $create): ?string
    {
        if (null !== self::$testKey) {
            return self::$testKey;
        }
        $file = rex_path::addonData(HubAddon::NAME, 'secret.key');
        if (is_file($file)) {
            $key = base64_decode(trim((string) rex_file::get($file)), true);
            if (\is_string($key) && SODIUM_CRYPTO_SECRETBOX_KEYBYTES === \strlen($key)) {
                return $key;
            }
        }
        if (!$create) {
            return null;
        }
        $key = sodium_crypto_secretbox_keygen();
        rex_file::put($file, base64_encode($key) . "\n");
        @chmod($file, 0600);

        return $key;
    }
}
