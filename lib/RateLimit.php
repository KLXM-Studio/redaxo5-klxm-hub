<?php

namespace Klxm\Hub;

use rex;
use rex_sql;

/**
 * Zähler mit Zeitfenster in der Tabelle rex_klxm_hub_hit (Schlüssel, Zeit) – für das Rate-Limit je IP und für die
 * schon gesehenen Nonces der Status-Abfrage. IP-Adressen werden nur als HMAC gespeichert.
 */
final class RateLimit
{
    private const int KEEP = 86400;

    /** @var array<string, list<int>>|null Speicher ohne Datenbank (Selbsttest) */
    public static ?array $memory = null;

    public static function table(): string
    {
        return HubAddon::table('hit');
    }

    public static function count(string $key, int $window): int
    {
        if (null !== self::$memory) {
            return \count(array_filter(self::$memory[$key] ?? [], static fn (int $t): bool => $t > time() - $window));
        }
        $sql = rex_sql::factory();
        $sql->setQuery('SELECT COUNT(*) AS n FROM ' . self::table() . ' WHERE k = ? AND t > ?', [self::hash($key), time() - $window]);

        return (int) $sql->getValue('n');
    }

    public static function hit(string $key): void
    {
        if (null !== self::$memory) {
            self::$memory[$key][] = time();

            return;
        }
        rex_sql::factory()->setTable(self::table())->setValue('k', self::hash($key))->setValue('t', time())->insert();
        // gelegentlich aufräumen
        if (1 === random_int(1, 50)) {
            rex_sql::factory()->setQuery('DELETE FROM ' . self::table() . ' WHERE t < ?', [time() - self::KEEP]);
        }
    }

    public static function tooMany(string $key, int $max, int $window): bool
    {
        return self::count($key, $window) >= $max;
    }

    /** Schlüssel für eine IP-Adresse (nicht im Klartext gespeichert) */
    public static function ip(string $prefix): string
    {
        return $prefix . ':ip:' . hash_hmac('sha256', self::clientIp(), self::pepper());
    }

    /** IP der Anfrage (hinter einem Proxy: Request::setTrustedProxies von Symfony, sonst REMOTE_ADDR) */
    public static function clientIp(): string
    {
        try {
            return (string) rex::getRequest()->getClientIp();
        } catch (\Throwable) {
            return 'cli';
        }
    }

    private static function hash(string $key): string
    {
        return hash('sha256', $key);
    }

    /** Geheimer Zusatz für die HMAC: instname der Installation (zufällig beim Setup erzeugt) */
    private static function pepper(): string
    {
        $p = (string) rex::getProperty('instname', '');

        return '' !== $p ? $p : 'klxm_hub';
    }
}
