<?php

namespace Klxm\Hub\Monitoring;

use Klxm\Hub\ExtensionPoint\HubStatus;
use Klxm\Hub\HubAddon;
use Klxm\Hub\Settings;
use rex;
use rex_addon;
use rex_dir;
use rex_extension;
use rex_file;
use rex_log_file;
use rex_logger;
use rex_path;
use rex_sql;

/**
 * Inhalt der Status-Antwort (status-v1, system „redaxo5“): Versionen von REDAXO und PHP, AddOns und PlugIns mit
 * Versionen, Ampel der Prüfungen mit Meldungen, letzte Sicherung, Fehlerprotokoll (nur Zahlen) – 60 Sekunden
 * zwischengespeichert, nonce wird je Anfrage angehängt. Keine Inhalte, keine Konten, keine Personendaten, keine
 * Geheimnisse, keine Serverpfade.
 *
 * Prüfungen (Fehler = rot, Hinweis = gelb; alle Kategorie „technical“):
 *   Fehler   Datenbank nicht erreichbar · Ordner (media, assets, cache, data) nicht beschreibbar · Setup ist offen
 *   Hinweis  Debug-Modus auf einer öffentlichen Website · Abgesicherter Modus (safe mode) · Verwaltung ohne HTTPS ·
 *            AddOns als Entwicklungsfassung (dev-…, …-dev) · OPcache aus · Anmeldung über den Hub an, aber kein lokaler
 *            Admin mit Passwort (Notfall-Zugang)
 * Fehlerprotokoll als eigenes Feld `log` (window_hours, errors, warnings) – der Hub bewertet es selbst.
 * Eigene Prüfungen und Sicherungen anderer Werkzeuge über den Erweiterungspunkt KLXM_HUB_STATUS ({@see HubStatus}).
 */
final class Status
{
    public const string SYSTEM = 'redaxo5';
    private const int CACHE_TTL = 60;

    public static function cacheFile(): string
    {
        return rex_path::addonCache(HubAddon::NAME, 'status.json');
    }

    /** @return array<string, mixed> */
    public static function collect(string $nonce): array
    {
        $file = self::cacheFile();
        $base = null;
        if (is_file($file) && filemtime($file) > time() - self::CACHE_TTL) {
            $base = json_decode((string) rex_file::get($file), true);
        }
        if (!\is_array($base)) {
            $base = self::build();
            rex_file::put($file, (string) json_encode($base, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
        }

        return $base + ['nonce' => $nonce];
    }

    private static function iso(?int $t): ?string
    {
        return $t ? date('c', $t) : null;
    }

    /** @return array<string, mixed> */
    public static function build(): array
    {
        /** @var list<array{level: string, category: string, text: string}> $msgs */
        $msgs = [];
        foreach (self::checks() as [$level, $text]) {
            $msgs[] = ['level' => $level, 'category' => 'technical', 'text' => mb_strimwidth($text, 0, 200, '…')];
        }

        $components = [];
        foreach (rex_addon::getInstalledAddons() as $addon) {
            $components[] = ['type' => 'addon', 'name' => $addon->getName(), 'version' => (string) $addon->getVersion(), 'active' => $addon->isAvailable()];
            foreach ($addon->getInstalledPlugins() as $plugin) {
                $components[] = ['type' => 'plugin', 'name' => $plugin->getPackageId(), 'version' => (string) $plugin->getVersion(), 'active' => $plugin->isAvailable()];
            }
        }

        $status = [
            'protocol' => Signature::PROTOCOL,
            'system' => self::SYSTEM,
            'system_version' => rex::getVersion(),
            'php' => PHP_VERSION,
            'generated_at' => date('c'),
            'site' => ['key' => 'default', 'url' => Settings::baseUrlFixed() ? Settings::baseUrl() : null],
            'components' => $components,
            'health' => [],
            'backup' => ['last_at' => self::iso(self::lastBackup()), 'offsite_at' => null],
            'integrity' => ['status' => 'unknown', 'checked_at' => null],
            'ssl' => ['expires_at' => null],   // ermittelt der Hub selbst aus der TLS-Verbindung
            // Fehlerprotokoll (nur Zahlen): schwere Fehler (Exceptions, Fatal/Error) und PHP-Warnungen der letzten 24 Stunden
            'log' => ['window_hours' => 24] + self::logCounts(86400),
        ];
        // Theme-AddOn (FriendsOfREDAXO/theme), falls vorhanden
        if (rex_addon::exists('theme') && rex_addon::get('theme')->isAvailable()) {
            $status['theme'] = ['name' => 'theme', 'version' => (string) rex_addon::get('theme')->getVersion()];
        }

        try {
            $ep = new HubStatus($status);
            $res = rex_extension::registerPoint($ep);
            $status = \is_array($res) ? $res : $status;
            foreach ($ep->messages as $m) {
                $cat = \in_array($m['category'] ?? '', ['technical', 'setup', 'editorial'], true) ? $m['category'] : 'technical';
                $msgs[] = ['level' => 'error' === $m['level'] ? 'error' : 'warning', 'category' => $cat, 'text' => mb_strimwidth((string) $m['text'], 0, 200, '…')];
            }
        } catch (\Throwable $e) {
            rex_logger::logException($e);
            $msgs[] = ['level' => 'error', 'category' => 'technical', 'text' => 'status extension failed'];
        }

        // Ampel und Zähler nur aus technischen Meldungen (status-v1, 4.1); technische vorn, Fehler vor Hinweisen
        $tech = array_values(array_filter($msgs, static fn (array $m): bool => 'technical' === $m['category']));
        $other = array_values(array_filter($msgs, static fn (array $m): bool => 'technical' !== $m['category']));
        usort($tech, static fn (array $a, array $b): int => ('error' === $b['level']) <=> ('error' === $a['level']));
        $err = \count(array_filter($tech, static fn (array $m): bool => 'error' === $m['level']));
        $warn = \count($tech) - $err;
        $status['health'] = ['status' => $err ? 'red' : ($warn ? 'yellow' : 'green'), 'errors' => $err, 'warnings' => $warn, 'notices' => \count($other),
            'messages' => \array_slice([...$tech, ...$other], 0, 50)];
        $status['protocol'] = Signature::PROTOCOL;
        $status['system'] = self::SYSTEM;
        unset($status['nonce']);

        return $status;
    }

    /** @return list<array{0: 'error'|'warning', 1: string}> */
    public static function checks(): array
    {
        $out = [];
        try {
            rex_sql::factory()->setQuery('SELECT 1');
        } catch (\Throwable) {
            $out[] = ['error', HubAddon::t('check_db')];
        }
        $notWritable = 0;
        foreach ([rex_path::media(), rex_path::assets(), rex_path::cache(), rex_path::data()] as $dir) {
            if (!is_dir($dir) || !rex_dir::isWritable($dir)) {
                ++$notWritable;
            }
        }
        if ($notWritable) {
            $out[] = ['error', HubAddon::t('check_writable', $notWritable)];
        }
        if (rex::isSetup()) {
            $out[] = ['error', HubAddon::t('check_setup')];
        }
        if (rex::isDebugMode() && self::publicHost()) {
            $out[] = ['warning', HubAddon::t('check_debug_mode')];
        }
        if (rex::isSafeMode() || rex::getProperty('safe_mode')) {
            $out[] = ['warning', HubAddon::t('check_safe_mode')];
        }
        if (self::publicHost() && !self::https()) {
            $out[] = ['warning', HubAddon::t('check_https')];
        }
        $dev = [];
        foreach (rex_addon::getAvailableAddons() as $addon) {
            $v = (string) $addon->getVersion();
            if (str_starts_with($v, 'dev-') || str_ends_with($v, '-dev')) {
                $dev[] = $addon->getName();
            }
        }
        if ($dev) {
            $out[] = ['warning', HubAddon::t('check_dev_addons', implode(', ', \array_slice($dev, 0, 10)))];
        }
        if (!(\function_exists('opcache_get_status') && \ini_get('opcache.enable')) && self::publicHost()) {
            $out[] = ['warning', HubAddon::t('check_opcache')];
        }
        if (Settings::oidc()['enabled'] && 0 === self::localAdmins()) {
            $out[] = ['warning', HubAddon::t('check_no_local_admin')];
        }

        return $out;
    }

    /** Läuft die Anfrage über HTTPS (auch hinter einem vertrauenswürdigen Proxy)? */
    private static function https(): bool
    {
        try {
            return rex::getRequest()->isSecure();
        } catch (\Throwable) {
            return str_starts_with((string) rex::getServer(), 'https://');
        }
    }

    /** Öffentliche Adresse? (nicht localhost/.localhost/.test/.local/private Netze) */
    private static function publicHost(): bool
    {
        try {
            $host = strtolower(rex::getRequest()->getHost());
        } catch (\Throwable) {
            return false;
        }
        if ('localhost' === $host || str_ends_with($host, '.localhost') || str_ends_with($host, '.test') || str_ends_with($host, '.local')
            || 'host.docker.internal' === $host) {
            return false;
        }

        return !filter_var($host, FILTER_VALIDATE_IP) || false !== filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
    }

    /**
     * Systemprotokoll der letzten $window Sekunden zählen (höchstens 2000 Einträge gelesen): errors = Exceptions und
     * Fehler, warnings = PHP-Warnungen. Hinweise (Info, Notice, Deprecated, Debug) und Zeilen dieses AddOns zählen nicht.
     *
     * @return array{errors: int, warnings: int}
     */
    public static function logCounts(int $window): array
    {
        $out = ['errors' => 0, 'warnings' => 0];
        $path = rex_logger::getPath();
        if (!is_file($path)) {
            return $out;
        }
        $read = 0;
        try {
            foreach (new rex_log_file($path) as $entry) {
                if ($entry->getTimestamp() < time() - $window || ++$read > 2000) {
                    break;
                }
                $data = $entry->getData();
                $level = strtolower((string) ($data[0] ?? ''));
                $msg = (string) ($data[1] ?? '');
                // rex_http_exception = Antwort an den Client (4xx), im Debug-Modus mitprotokolliert – kein Serverfehler;
                // Warnung von rex_socket bei http (nur mit KLXM_HUB_ALLOW_HTTP=1) ebenso nicht
                if (str_starts_with($msg, 'klxm_hub:') || str_ends_with($level, 'http_exception') || str_ends_with($level, 'httpexception')
                    || str_starts_with($msg, 'You should not use non-secure socket connections')
                    || \in_array($level, ['info', 'notice', 'debug', 'deprecated', 'user deprecated', 'user notice'], true)) {
                    continue;
                }
                \in_array($level, ['warning', 'user warning', 'core warning', 'compile warning'], true) ? ++$out['warnings'] : ++$out['errors'];
            }
        } catch (\Throwable) {
        }

        return $out;
    }

    /** Aktive Admins mit Passwort (Notfall-Zugang ohne Hub) */
    public static function localAdmins(): int
    {
        try {
            $sql = rex_sql::factory();
            $sql->setQuery('SELECT COUNT(*) AS n FROM ' . rex::getTable('user') . ' WHERE admin = 1 AND status = 1 AND password IS NOT NULL AND password <> ""');

            return (int) $sql->getValue('n');
        } catch (\Throwable) {
            return 0;
        }
    }

    /**
     * Zeit der neuesten Sicherung: Dateien (*.sql, *.sql.gz, *.tar.gz, *.tgz, *.zip) im eingestellten Ordner
     * (Einstellungen → Überwachung; absolut oder relativ zum Projektordner) bzw. im Ordner des AddOns backup
     * (redaxo/data/addons/backup). Andere Werkzeuge melden ihre Sicherung über KLXM_HUB_STATUS.
     */
    public static function lastBackup(): ?int
    {
        $dirs = [rex_path::addonData('backup')];
        $own = Settings::monitor()['backup_dir'];
        if ('' !== $own) {
            array_unshift($dirs, str_starts_with($own, '/') ? $own : rex_path::base($own));
        }
        $latest = 0;
        foreach ($dirs as $dir) {
            if (!is_dir($dir)) {
                continue;
            }
            // eine Ebene tief (z. B. backup-deploy-2026…/db.sql.gz)
            foreach ([...(glob(rtrim($dir, '/') . '/*') ?: []), ...(glob(rtrim($dir, '/') . '/*/*') ?: [])] as $f) {
                if (is_file($f) && preg_match('~\.(sql|sql\.gz|tar\.gz|tgz|zip)$~i', $f)) {
                    $latest = max($latest, (int) @filemtime($f));
                }
            }
        }

        return $latest ?: null;
    }
}
