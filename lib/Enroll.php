<?php

namespace Klxm\Hub;

use Klxm\Hub\Monitoring\Signature;
use Klxm\Hub\Monitoring\Status;
use Klxm\Hub\Oidc\Client;
use Klxm\Hub\Oidc\Jwk;

/**
 * Verbindung mit dem Agentur Hub per Einmal-Code (klxm-instance-v1, „enroll“, wie KLXM Studio `Core\InstanceEnroll` und die
 * Fassung für REDAXO 6).
 *
 * Ein Admin erzeugt in den Einstellungen einen Code (15 Minuten, einmal verwendbar). Er enthält die Adresse der Website,
 * den Endpunkt und ein Geheimnis; gespeichert wird nur dessen Hash (rex_config klxm_hub/enroll). Der Hub ruft auf:
 *   POST /index.php?rex-api-call=klxm_hub_enroll  (JSON)
 *   step=hello    → Name, Anmelde-Adressen, Status-Adresse (Code bleibt gültig)
 *   step=complete → Issuer, Client-ID/-Geheimnis, öffentliche Überwachungsschlüssel → Anmeldung und Überwachung eingeschaltet,
 *                   Code verbraucht
 * Ohne offenen Code: 401. Fehlversuche je IP begrenzt (10 in 15 Minuten) und im Systemprotokoll vermerkt.
 */
final class Enroll
{
    public const string PREFIX = 'KLXM1.';
    public const int TTL = 900;

    /** Neuen Code erzeugen (ersetzt einen offenen) */
    public static function create(string $by): string
    {
        $token = Jwk::b64u(random_bytes(24));
        HubAddon::addon()->setConfig('enroll', ['hash' => hash('sha256', $token), 'expires' => time() + self::TTL, 'by' => $by, 'created' => time()]);
        $site = rtrim(Client::siteUrl(), '/');

        return self::PREFIX . Jwk::b64u((string) json_encode(['u' => $site, 'e' => $site . '/index.php?rex-api-call=klxm_hub_enroll', 't' => $token], JSON_UNESCAPED_SLASHES));
    }

    /** @return array{expires: int, by: string}|null */
    public static function pending(): ?array
    {
        $p = HubAddon::addon()->getConfig('enroll', []);

        return \is_array($p) && !empty($p['hash']) && (int) ($p['expires'] ?? 0) >= time() ? ['expires' => (int) $p['expires'], 'by' => (string) ($p['by'] ?? '')] : null;
    }

    public static function cancel(): void
    {
        HubAddon::addon()->removeConfig('enroll');
    }

    /** @return array{issuer: string, at: int}|null */
    public static function done(): ?array
    {
        $d = HubAddon::addon()->getConfig('enroll_done', []);

        return \is_array($d) && !empty($d['issuer']) ? ['issuer' => (string) $d['issuer'], 'at' => (int) ($d['at'] ?? 0)] : null;
    }

    /**
     * Anfrage des Hubs.
     *
     * @param array<string, mixed> $in
     *
     * @return array{0: int, 1: array<string, mixed>}
     */
    public static function handle(array $in): array
    {
        $ipKey = RateLimit::ip('enroll');
        if (RateLimit::tooMany($ipKey, 10, 900)) {
            return [429, ['error' => 'too_many_requests']];
        }
        $p = HubAddon::addon()->getConfig('enroll', []);
        $token = (string) ($in['token'] ?? '');
        $valid = \is_array($p) && !empty($p['hash']) && (int) ($p['expires'] ?? 0) >= time() && '' !== $token && hash_equals((string) $p['hash'], hash('sha256', $token));
        if (!$valid) {
            RateLimit::hit($ipKey);
            Log::write('warning', 'enroll-failed');

            return [401, ['error' => 'invalid_code', 'error_description' => HubAddon::t('enroll_invalid')]];
        }
        $step = (string) ($in['step'] ?? 'hello');
        if ('hello' === $step) {
            return [200, self::info()];
        }
        if ('complete' !== $step) {
            return [400, ['error' => 'invalid_step']];
        }
        $issuer = rtrim(trim((string) ($in['issuer'] ?? '')), '/');
        $cid = trim((string) ($in['client_id'] ?? ''));
        $secret = (string) ($in['client_secret'] ?? '');
        $keys = array_values(array_filter((array) ($in['monitoring_keys'] ?? []), static fn ($k): bool => \is_string($k) && null !== Signature::parseKey($k)));
        if ('' === $cid || '' === $secret || !preg_match('~^https://[^\s/?#]+(/[^\s?#]*)?$~', $issuer)) {
            return [400, ['error' => 'invalid_request']];
        }
        try {
            Client::discovery($issuer, true);
        } catch (\Throwable $e) {
            return [400, ['error' => 'issuer_unreachable', 'error_description' => mb_strimwidth($e->getMessage(), 0, 160, '…')]];
        }
        $name = mb_substr(trim((string) ($in['name'] ?? '')), 0, 60) ?: 'Agentur Hub';
        $old = Settings::oidc();
        Settings::saveOidc(['enabled' => 1, 'name' => $name, 'issuer' => $issuer, 'client_id' => $cid, 'client_secret' => $secret,
            'auth' => 'client_secret_basic', 'jit' => $old['jit'] ? 1 : 0, 'role_redaktion' => $old['role_redaktion']]);
        Client::forgetCache($issuer);
        try {
            Logo::refresh($issuer);   // Logo des Anbieters für den Anmelde-Link, optional
        } catch (\Throwable) {
        }
        $m = Settings::monitor();
        $lines = array_map(static fn (array $k): string => trim($k['label'] . ' ' . $k['key']), $m['keys']);
        foreach ($keys as $k) {
            if (!\in_array($k, array_column($m['keys'], 'key'), true)) {
                $lines[] = $name . ' ' . $k;
            }
        }
        $monitor = $keys && null === Settings::saveMonitor(true, implode("\n", $lines), $m['backup_dir']);
        @unlink(Status::cacheFile());
        HubAddon::addon()->removeConfig('enroll');
        HubAddon::addon()->setConfig('enroll_done', ['issuer' => $issuer, 'name' => $name, 'at' => time(), 'monitor' => $monitor, 'by' => (string) ($p['by'] ?? '')]);
        Log::write('info', 'enrolled', ['issuer' => $issuer, 'monitor' => (int) $monitor]);

        return [200, ['ok' => true] + self::info()];
    }

    /** Auskunft für den Hub (wie die Selbstauskunft, unabhängig davon, ob schon etwas eingerichtet ist) @return array<string, mixed> */
    public static function info(): array
    {
        $base = Client::siteUrl();

        return [
            'spec' => InstanceInfo::SPEC, 'system' => Status::SYSTEM, 'name' => InstanceInfo::name(),
            'login' => ['redirect_uri' => Client::redirectUri(), 'initiate_login_uri' => Client::startUri(), 'post_logout_redirect_uri' => Client::logoutUri()],
            'monitoring' => ['status_url' => Client::statusUri(), 'sites' => [['key' => 'default', 'name' => InstanceInfo::name(), 'url' => $base, 'status_url' => Client::statusUri()]]],
        ];
    }
}
