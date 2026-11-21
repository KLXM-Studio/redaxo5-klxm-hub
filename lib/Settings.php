<?php

namespace Klxm\Hub;

use Klxm\Hub\Monitoring\Signature;
use rex;

/**
 * Einstellungen des AddOns (rex_config, Namespace klxm_hub) – alles ist standardmäßig aus.
 *
 *   oidc     Anmeldung über den Hub: Schalter, Name, Issuer, Client-ID, Client-Geheimnis (verschlüsselt, {@see Secret}),
 *            Verfahren am Token-Endpunkt, Konto bei der ersten Anmeldung anlegen, Rolle für „redaktion“
 *   monitor  Signierte Status-Abfrage: Schalter, öffentliche Schlüssel des Hubs (ed25519:…), Ordner mit Sicherungen
 *
 * Umgebungsvariablen ({@see Env}) haben Vorrang und stehen dann nicht in der Datenbank:
 *   KLXM_HUB_CLIENT_SECRET   Client-Geheimnis
 */
final class Settings
{
    public const array OIDC_DEFAULTS = [
        'enabled' => false,
        'name' => 'Agentur Hub',
        'issuer' => '',
        'client_id' => '',
        'client_secret_enc' => '',
        'auth' => 'client_secret_basic',   // client_secret_basic | client_secret_post
        'jit' => true,
        'role_redaktion' => 0,
    ];

    public const array MONITOR_DEFAULTS = [
        'enabled' => false,
        'keys' => [],
        'backup_dir' => '',
    ];

    /** Für den Selbsttest: Einstellungen ohne Datenbank */
    public static ?array $override = null;

    /**
     * Anmeldung über den Hub (mit entschlüsseltem Geheimnis in client_secret).
     *
     * @return array{enabled: bool, name: string, issuer: string, client_id: string, client_secret: string, secret_from_env: bool, auth: string, jit: bool, role_redaktion: int}
     */
    public static function oidc(): array
    {
        $raw = self::$override['oidc'] ?? HubAddon::addon()->getConfig('oidc', []);
        $p = array_replace(self::OIDC_DEFAULTS, array_intersect_key(\is_array($raw) ? $raw : [], self::OIDC_DEFAULTS));
        $env = Env::get('KLXM_HUB_CLIENT_SECRET');
        $secret = $env ?? Secret::decrypt((string) $p['client_secret_enc']);
        if (isset(self::$override['oidc']['client_secret'])) {
            $secret = (string) self::$override['oidc']['client_secret'];
        }

        return [
            'enabled' => (bool) $p['enabled'],
            'name' => trim((string) $p['name']) ?: 'Agentur Hub',
            'issuer' => rtrim(trim((string) $p['issuer']), '/'),
            'client_id' => trim((string) $p['client_id']),
            'client_secret' => $secret,
            'secret_from_env' => null !== $env,
            'auth' => 'client_secret_post' === $p['auth'] ? 'client_secret_post' : 'client_secret_basic',
            'jit' => (bool) $p['jit'],
            'role_redaktion' => (int) $p['role_redaktion'],
        ];
    }

    /** Vollständig eingerichtet und eingeschaltet? */
    public static function oidcReady(?array $s = null): bool
    {
        $s ??= self::oidc();

        return $s['enabled'] && '' !== $s['issuer'] && '' !== $s['client_id'] && '' !== $s['client_secret'];
    }

    /**
     * Speichern. Leeres Geheimnis = bisheriges behalten.
     *
     * @param array<string, mixed> $in
     */
    public static function saveOidc(array $in): void
    {
        $old = HubAddon::addon()->getConfig('oidc', []);
        $old = \is_array($old) ? $old : [];
        $secret = (string) ($in['client_secret'] ?? '');
        HubAddon::addon()->setConfig('oidc', [
            'enabled' => !empty($in['enabled']),
            'name' => mb_substr(trim((string) ($in['name'] ?? '')), 0, 60),
            'issuer' => rtrim(trim((string) ($in['issuer'] ?? '')), '/'),
            'client_id' => mb_substr(trim((string) ($in['client_id'] ?? '')), 0, 191),
            'client_secret_enc' => '' !== $secret ? Secret::encrypt($secret) : (string) ($old['client_secret_enc'] ?? ''),
            'auth' => 'client_secret_post' === ($in['auth'] ?? '') ? 'client_secret_post' : 'client_secret_basic',
            'jit' => !empty($in['jit']),
            'role_redaktion' => (int) ($in['role_redaktion'] ?? 0),
        ]);
    }

    public static function forgetSecret(): void
    {
        $old = HubAddon::addon()->getConfig('oidc', []);
        HubAddon::addon()->setConfig('oidc', ['client_secret_enc' => ''] + (\is_array($old) ? $old : []));
    }

    /**
     * Überwachung.
     *
     * @return array{enabled: bool, keys: list<array{label: string, key: string, added: int}>, backup_dir: string}
     */
    public static function monitor(): array
    {
        $raw = self::$override['monitor'] ?? HubAddon::addon()->getConfig('monitor', []);
        $raw = array_replace(self::MONITOR_DEFAULTS, \is_array($raw) ? $raw : []);
        $keys = [];
        foreach ((array) $raw['keys'] as $k) {
            $k = \is_string($k) ? ['key' => $k] : (array) $k;
            if (null === Signature::parseKey((string) ($k['key'] ?? ''))) {
                continue;
            }
            $keys[] = ['label' => mb_substr((string) ($k['label'] ?? ''), 0, 60), 'key' => trim((string) $k['key']), 'added' => (int) ($k['added'] ?? 0)];
        }

        return ['enabled' => (bool) $raw['enabled'], 'keys' => \array_slice($keys, 0, Signature::MAX_KEYS), 'backup_dir' => trim((string) $raw['backup_dir'])];
    }

    /**
     * Speichern: Zeilen „Bezeichnung ed25519:…“ bzw. nur „ed25519:…“.
     *
     * @return string|null Fehlertext
     */
    public static function saveMonitor(bool $enabled, string $keysText, string $backupDir): ?string
    {
        $old = [];
        foreach (self::monitor()['keys'] as $k) {
            $old[$k['key']] = $k;
        }
        $keys = [];
        foreach (preg_split('~\R~', $keysText) ?: [] as $line) {
            $line = trim($line);
            if ('' === $line) {
                continue;
            }
            if (!preg_match('~^(.*?)\s*(ed25519:[A-Za-z0-9_-]+)$~', $line, $m) || null === Signature::parseKey($m[2])) {
                return HubAddon::t('monitor_key_invalid', mb_strimwidth($line, 0, 60, '…'));
            }
            $keys[$m[2]] = ['label' => mb_substr(trim($m[1]), 0, 60), 'key' => $m[2], 'added' => $old[$m[2]]['added'] ?? time()];
        }
        if (\count($keys) > Signature::MAX_KEYS) {
            return HubAddon::t('monitor_key_too_many', Signature::MAX_KEYS);
        }
        if ($enabled && !$keys) {
            return HubAddon::t('monitor_key_required');
        }
        HubAddon::addon()->setConfig('monitor', ['enabled' => $enabled, 'keys' => array_values($keys), 'backup_dir' => mb_substr(trim($backupDir), 0, 500)]);

        return null;
    }

    /**
     * Adresse der Website (Grundlage für Redirect-URI, Einstieg, Status-Adresse und Selbsttest): System → Einstellungen →
     * „URL der Website“ (rex::getServer()). Fehlt sie oder steht dort noch die Vorgabe von REDAXO, bleibt nur der Host der
     * Anfrage – die Einstellungen warnen dann ({@see self::baseUrlFixed()}).
     */
    public static function baseUrl(): string
    {
        if (self::baseUrlFixed()) {
            return rtrim((string) rex::getServer(), '/') . '/';
        }
        try {
            $r = rex::getRequest();

            return $r->getSchemeAndHttpHost() . '/';
        } catch (\Throwable) {
            return 'https://localhost/';
        }
    }

    /** Ist die Adresse der Website fest eingestellt (nicht leer, http(s), nicht die Vorgabe redaxo.org)? */
    public static function baseUrlFixed(): bool
    {
        $s = (string) rex::getServer();

        return (bool) preg_match('~^https?://[^\s/?#]+(/[^\s?#]*)?$~', $s) && !preg_match('~^https?://(www\.)?redaxo\.org/?$~i', $s);
    }
}
