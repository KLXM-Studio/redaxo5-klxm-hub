<?php

namespace Klxm\Hub;

/**
 * Umgebungsvariablen (REDAXO 5 hat kein .env): getenv() bzw. $_SERVER/$_ENV – gesetzt z. B. per `SetEnv` in der
 * Apache-Konfiguration, `env[…]` im PHP-FPM-Pool oder beim Start von `php -S`.
 *
 *   KLXM_HUB_CLIENT_SECRET            Client-Geheimnis (steht dann nicht in der Datenbank)
 *   KLXM_HUB_ALLOW_PRIVATE_NETWORK=1  Abrufe beim Anbieter auch an private/lokale Adressen (Hub im eigenen Netz)
 *   KLXM_HUB_ALLOW_HTTP=1             Anbieter auch ohne https (nur für Tests im lokalen Netz)
 */
final class Env
{
    /** @var array<string, string>|null Selbsttest: feste Werte */
    public static ?array $override = null;

    public static function get(string $name): ?string
    {
        if (null !== self::$override) {
            return self::$override[$name] ?? null;
        }
        $v = getenv($name);
        if (false === $v || '' === $v) {
            $v = $_SERVER[$name] ?? $_ENV[$name] ?? null;
        }

        return \is_string($v) && '' !== $v ? $v : null;
    }

    public static function flag(string $name): bool
    {
        return '1' === self::get($name);
    }
}
