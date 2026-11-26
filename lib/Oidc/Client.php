<?php

namespace Klxm\Hub\Oidc;

use Klxm\Hub\HubAddon;
use Klxm\Hub\Http;
use Klxm\Hub\Settings;
use rex_file;
use rex_login;
use rex_path;
use rex_url;

/**
 * OpenID-Connect-Client (Relying Party) gegen den Hub: Authorization Code Flow mit PKCE (S256), state und nonce.
 *
 *  - Discovery: {issuer}/.well-known/openid-configuration, „issuer“ muss exakt passen, PKCE S256 muss angeboten sein;
 *    1 Stunde im Cache des AddOns.
 *  - JWKS: 1 Stunde im Cache; unbekannte kid → einmal neu laden (Schlüsselwechsel beim Anbieter), höchstens alle 60 Sekunden.
 *  - ID-Token: RS256 ({@see Jwt}), iss, aud (+ azp), exp/iat mit 60 s Toleranz, iat nicht älter als 10 Minuten, nonce,
 *    at_hash, sub. Zweiter Faktor über amr ({@see self::strongAmr()}).
 *  - Offene Anmeldungen liegen in der Backend-Sitzung (Schlüssel klxm_hub): je state nonce, code_verifier und
 *    Redirect-URI – 10 Minuten gültig, höchstens 5 gleichzeitig, einmal verwendbar.
 *  - Endpunkte nur per https; http nur mit KLXM_HUB_ALLOW_HTTP=1 (Tests im lokalen Netz) bzw. im Selbsttest.
 */
final class Client
{
    public const int LEEWAY = 60;
    public const int MAX_AGE = 600;
    public const int PENDING_TTL = 600;
    private const int CACHE_TTL = 3600;
    private const string SESSION_KEY = 'klxm_hub';

    /** Uhr (Selbsttest) */
    public static ?int $now = null;
    /** @var array<string, array<mixed>> Zwischenspeicher im Speicher (Selbsttest) */
    private static array $mem = [];
    /** @var array<string, array<mixed>>|null offene Anmeldungen ohne Sitzung (Selbsttest) */
    public static ?array $pendingMemory = null;

    public static function now(): int
    {
        return self::$now ?? time();
    }

    public static function resetForTest(): void
    {
        self::$mem = [];
        self::$pendingMemory = [];
    }

    /** Redirect-URI dieser Installation (beim Hub exakt so registriert) */
    public static function redirectUri(): string
    {
        return self::backendUrl(['rex-api-call' => 'klxm_hub', 'step' => 'callback']);
    }

    /** Einstieg (Knopf auf der Anmeldeseite, „Öffnen“ im Hub) */
    public static function startUri(): string
    {
        return self::backendUrl(['rex-api-call' => 'klxm_hub', 'step' => 'start']);
    }

    /** Adresse nach dem Abmelden (post_logout_redirect_uri): Anmeldeseite des Backends */
    public static function logoutUri(): string
    {
        return preg_replace('~\?.*$~', '', self::startUri()) ?? self::startUri();
    }

    /** Status-Adresse (Frontend, status-v1) */
    public static function statusUri(): string
    {
        $base = self::$baseOverride ?? Settings::baseUrl();

        return rtrim($base, '/') . '/index.php?rex-api-call=klxm_hub_status';
    }

    /**
     * Einstieg als relative Adresse (Link auf der Anmeldeseite) – hängt nie am Host der Anfrage, auch wenn die Adresse
     * der Website nicht eingestellt ist (keine Host-Header-Einschleusung in die Seite).
     */
    public static function startLink(): string
    {
        return rex_url::backendController(['rex-api-call' => 'klxm_hub', 'step' => 'start'], false);
    }

    /** Für den Selbsttest: feste Basis statt Settings::baseUrl() */
    public static ?string $baseOverride = null;

    /** Adresse der Website (mit Schrägstrich am Ende) – Selbsttest kann sie über $baseOverride setzen */
    public static function siteUrl(): string
    {
        return self::$baseOverride ?? Settings::baseUrl();
    }

    /**
     * Absolute Adresse im Backend: Basis der Website (System → URL der Website bzw. Host der Anfrage) + Ordner des Backends
     * (meist „redaxo“) + index.php mit Parametern – genau so wird sie beim Hub registriert.
     *
     * @param array<string, string> $params
     */
    private static function backendUrl(array $params): string
    {
        $base = self::$baseOverride ?? Settings::baseUrl();
        $dir = self::$baseOverride ? 'redaxo' : basename(rtrim(rex_path::backend(), '/'));

        return rtrim($base, '/') . '/' . $dir . '/index.php?' . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }

    // ================================================================= Abrufe

    /** @return array<mixed> */
    private static function json(string $url): array
    {
        try {
            $r = Http::request('GET', $url);
        } catch (\Throwable $e) {
            throw new OidcException('fetch', HubAddon::t('err_provider_unreachable'));
        }
        $j = json_decode($r['body'], true);
        if (200 !== $r['status'] || !\is_array($j)) {
            throw new OidcException('fetch:' . $r['status'], HubAddon::t('err_provider_unreachable'));
        }

        return $j;
    }

    private static function cacheFile(string $kind, string $key): string
    {
        return rex_path::addonCache(HubAddon::NAME, $kind . '-' . substr(hash('sha256', $key), 0, 24) . '.json');
    }

    /**
     * @param callable(): array<mixed> $load
     * @return array<mixed>
     */
    private static function cached(string $kind, string $key, bool $force, callable $load): array
    {
        if (null !== Http::$transport) {
            $mk = $kind . '|' . $key;
            if (!$force && isset(self::$mem[$mk])) {
                return self::$mem[$mk];
            }

            return self::$mem[$mk] = $load();
        }
        $f = self::cacheFile($kind, $key);
        if (!$force && is_file($f) && filemtime($f) > time() - self::CACHE_TTL) {
            $j = json_decode((string) rex_file::get($f), true);
            if (\is_array($j)) {
                return $j;
            }
        }
        $j = $load();
        rex_file::put($f, (string) json_encode($j, JSON_UNESCAPED_SLASHES));

        return $j;
    }

    public static function forgetCache(string $issuer): void
    {
        if ('' !== $issuer) {
            @unlink(self::cacheFile('disc', $issuer));
        }
    }

    /**
     * Discovery-Dokument (geprüft).
     *
     * @return array<mixed>
     */
    public static function discovery(string $issuer, bool $force = false): array
    {
        return self::cached('disc', $issuer, $force, static function () use ($issuer): array {
            if (!self::safeEndpoint($issuer)) {
                throw new OidcException('issuer_insecure', HubAddon::t('err_issuer_insecure'));
            }
            $d = self::json($issuer . '/.well-known/openid-configuration');
            if ('' === (string) ($d['issuer'] ?? '') || !hash_equals($issuer, rtrim((string) $d['issuer'], '/'))) {
                throw new OidcException('discovery:issuer', HubAddon::t('err_discovery'));
            }
            foreach (['authorization_endpoint', 'token_endpoint', 'jwks_uri'] as $k) {
                if (!self::safeEndpoint((string) ($d[$k] ?? ''))) {
                    throw new OidcException('discovery:' . $k, HubAddon::t('err_discovery'));
                }
            }
            if (!\in_array('S256', (array) ($d['code_challenge_methods_supported'] ?? []), true)) {
                throw new OidcException('discovery:pkce', HubAddon::t('err_discovery'));
            }

            return $d;
        });
    }

    private static function safeEndpoint(string $u): bool
    {
        if (preg_match('~^https://[^\s/?#]+~', $u)) {
            return true;
        }

        return (bool) preg_match('~^http://[^\s/?#]+~', $u) && (null !== Http::$transport || Http::allowHttp());
    }

    /** @return array<mixed> */
    public static function jwks(string $uri, bool $force = false): array
    {
        return self::cached('jwks', $uri, $force, static function () use ($uri): array {
            $j = self::json($uri);
            if (!isset($j['keys']) || !\is_array($j['keys'])) {
                throw new OidcException('jwks', HubAddon::t('err_provider_unreachable'));
            }

            return ['keys' => array_values(array_filter($j['keys'], 'is_array'))];
        });
    }

    // ================================================================= Sitzung

    /** @return array<string, array<mixed>> */
    private static function getPending(): array
    {
        if (null !== self::$pendingMemory) {
            return self::$pendingMemory;
        }
        rex_login::startSession();
        $v = rex_session(self::SESSION_KEY, 'array', []);

        return \is_array($v) ? $v : [];
    }

    /** @param array<string, array<mixed>> $v */
    private static function setPending(array $v): void
    {
        if (null !== self::$pendingMemory) {
            self::$pendingMemory = $v;

            return;
        }
        rex_login::startSession();
        rex_set_session(self::SESSION_KEY, $v);
    }

    /** @return array<string, array<mixed>> gültige offene Anmeldungen */
    private static function pending(): array
    {
        $out = [];
        foreach (self::getPending() as $s => $v) {
            if (\is_array($v) && (int) ($v['at'] ?? 0) > self::now() - self::PENDING_TTL) {
                $out[(string) $s] = $v;
            }
        }

        return $out;
    }

    // ================================================================= Ablauf

    /** PKCE: code_verifier → code_challenge (S256, RFC 7636) */
    public static function challenge(string $verifier): string
    {
        return Jwk::b64u(hash('sha256', $verifier, true));
    }

    /**
     * Anmeldung beginnen: offene Anmeldung in der Sitzung merken.
     *
     * @param array{issuer: string, client_id: string} $p
     * @return string Adresse beim Anbieter
     */
    public static function begin(array $p, string $loginHint = ''): string
    {
        $d = self::discovery($p['issuer']);
        $state = Jwk::b64u(random_bytes(32));
        $nonce = Jwk::b64u(random_bytes(32));
        $verifier = Jwk::b64u(random_bytes(48));
        $redirect = self::redirectUri();
        $pending = self::pending();
        $pending[$state] = ['n' => $nonce, 'v' => $verifier, 'at' => self::now(), 'r' => $redirect, 'iss' => $p['issuer']];
        // höchstens 5 offene Anmeldungen je Sitzung (älteste fallen weg)
        uasort($pending, static fn (array $a, array $b): int => $b['at'] <=> $a['at']);
        self::setPending(\array_slice($pending, 0, 5, true));
        $q = ['response_type' => 'code', 'client_id' => $p['client_id'], 'redirect_uri' => $redirect, 'scope' => 'openid email profile roles',
            'state' => $state, 'nonce' => $nonce, 'code_challenge' => self::challenge($verifier), 'code_challenge_method' => 'S256'];
        if ('' !== $loginHint) {
            $q['login_hint'] = mb_substr($loginHint, 0, 191);
        }
        $ep = (string) $d['authorization_endpoint'];

        return $ep . (str_contains($ep, '?') ? '&' : '?') . http_build_query($q, '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * Offene Anmeldung zum state holen und sofort verbrauchen (einmal verwendbar).
     *
     * @return array<mixed>|null
     */
    public static function takeState(string $state): ?array
    {
        $pending = self::pending();
        $hit = null;
        foreach ($pending as $s => $v) {
            if (\strlen($state) >= 43 && hash_equals((string) $s, $state)) {
                $hit = $v;
                unset($pending[$s]);
                break;
            }
        }
        self::setPending($pending);

        return $hit;
    }

    /** Alle offenen Anmeldungen der Sitzung verwerfen (nach erfolgreicher Anmeldung) */
    public static function forgetPending(): void
    {
        self::setPending([]);
    }

    /**
     * Rückkehr vom Anbieter: Code einlösen und ID-Token prüfen.
     *
     * @param array{issuer: string, client_id: string, client_secret: string, auth: string} $p
     * @param array<mixed> $pend
     * @throws OidcException
     * @return array{claims: array<mixed>, id_token: string}
     */
    public static function finish(array $p, array $pend, string $code): array
    {
        if ('' === $code || \strlen($code) > 2048) {
            throw new OidcException('code', HubAddon::t('err_generic'));
        }
        $d = self::discovery($p['issuer']);
        $form = ['grant_type' => 'authorization_code', 'code' => $code, 'redirect_uri' => (string) $pend['r'], 'code_verifier' => (string) $pend['v']];
        $headers = ['Content-Type' => 'application/x-www-form-urlencoded'];
        if ('client_secret_post' === $p['auth']) {
            $form += ['client_id' => $p['client_id'], 'client_secret' => $p['client_secret']];
        } else {
            // RFC 6749 2.3.1: Kennung und Geheimnis URL-kodiert in Basic
            $headers['Authorization'] = 'Basic ' . base64_encode(rawurlencode($p['client_id']) . ':' . rawurlencode($p['client_secret']));
            $form['client_id'] = $p['client_id'];
        }
        try {
            $r = Http::request('POST', (string) $d['token_endpoint'], $headers, http_build_query($form, '', '&', PHP_QUERY_RFC3986));
        } catch (\Throwable) {
            throw new OidcException('token:fetch', HubAddon::t('err_provider_unreachable'));
        }
        $tok = json_decode($r['body'], true);
        if (200 !== $r['status'] || !\is_array($tok)) {
            $err = \is_array($tok) ? preg_replace('~[^\w.-]~', '', (string) ($tok['error'] ?? '')) : '';
            throw new OidcException('token:' . ($err ?: 'http' . $r['status']), HubAddon::t('err_code_rejected'));
        }
        if ('bearer' !== strtolower((string) ($tok['token_type'] ?? 'bearer')) || !\is_string($tok['id_token'] ?? null)) {
            throw new OidcException('token:no_id_token', HubAddon::t('err_generic'));
        }
        $claims = self::validateIdToken($p, $d, $tok['id_token'], (string) $pend['n'], \is_string($tok['access_token'] ?? null) ? $tok['access_token'] : null);

        return ['claims' => $claims, 'id_token' => $tok['id_token']];
    }

    /**
     * ID-Token prüfen (Signatur mit Schlüsselwechsel, Claims).
     *
     * @param array{issuer: string, client_id: string} $p
     * @param array<mixed> $d Discovery
     * @throws OidcException
     * @return array<mixed>
     */
    public static function validateIdToken(array $p, array $d, string $idt, string $nonce, ?string $accessToken = null): array
    {
        $fail = static fn (string $why): OidcException => new OidcException('id_token:' . $why, HubAddon::t('err_token_invalid'));
        try {
            try {
                [, $c] = Jwt::verify($idt, self::jwks((string) $d['jwks_uri']));
            } catch (JwtException $e) {
                if (!\in_array($e->getMessage(), ['unknown_kid', 'no_key'], true) || !self::mayRefresh((string) $d['jwks_uri'])) {
                    throw $e;
                }
                [, $c] = Jwt::verify($idt, self::jwks((string) $d['jwks_uri'], true));   // Schlüsselwechsel beim Anbieter
            }
        } catch (JwtException $e) {
            throw $fail($e->getMessage());
        }
        $now = self::now();
        if (!\is_string($c['iss'] ?? null) || !hash_equals($p['issuer'], rtrim($c['iss'], '/'))) {
            throw $fail('iss');
        }
        // aud: Text oder Liste von Texten (andere Werte zählen nicht – keine Warnung „Array to string“)
        $aud = \is_array($c['aud'] ?? null) ? array_values(array_filter($c['aud'], 'is_string')) : (\is_string($c['aud'] ?? null) ? [$c['aud']] : []);
        if (!\in_array($p['client_id'], $aud, true)) {
            throw $fail('aud');
        }
        if ((\count($aud) > 1 || isset($c['azp'])) && ($c['azp'] ?? null) !== $p['client_id']) {
            throw $fail('azp');
        }
        if (!is_numeric($c['exp'] ?? null) || (int) $c['exp'] < $now - self::LEEWAY) {
            throw $fail('exp');
        }
        if (!is_numeric($c['iat'] ?? null) || (int) $c['iat'] > $now + self::LEEWAY || (int) $c['iat'] < $now - self::MAX_AGE) {
            throw $fail('iat');
        }
        if (isset($c['nbf']) && (int) $c['nbf'] > $now + self::LEEWAY) {
            throw $fail('nbf');
        }
        if (!\is_string($c['nonce'] ?? null) || '' === $nonce || !hash_equals($nonce, $c['nonce'])) {
            throw $fail('nonce');
        }
        if (!\is_string($c['sub'] ?? null) || '' === $c['sub'] || \strlen($c['sub']) > 191) {
            throw $fail('sub');
        }
        // at_hash: Pflicht, wenn ein Access-Token mitkommt (bindet es an das ID-Token)
        if (null !== $accessToken && (!\is_string($c['at_hash'] ?? null) || !hash_equals(Jwt::halfHash($accessToken), $c['at_hash']))) {
            throw $fail('at_hash');
        }

        return $c;
    }

    /** Schlüssel neu laden höchstens alle 60 Sekunden je JWKS */
    private static function mayRefresh(string $uri): bool
    {
        if (null !== Http::$transport) {
            return true;
        }
        $f = self::cacheFile('jwks', $uri);

        return !is_file($f) || filemtime($f) < time() - 60;
    }

    /**
     * Belegt das Token einen zweiten Faktor? (amr nach RFC 8176; „pwd“ allein reicht nicht)
     *
     * @param array<mixed> $claims
     */
    public static function strongAmr(array $claims): bool
    {
        $amr = array_filter((array) ($claims['amr'] ?? []), 'is_string');

        return (bool) array_intersect($amr, ['mfa', 'otp', 'hwk', 'swk', 'sc', 'fpt', 'face', 'iris', 'retina', 'vbm']);
    }

    /**
     * Rollen aus dem Claim „roles“ (Liste oder durch Leerzeichen getrennt).
     *
     * @param array<mixed> $claims
     * @return list<string>
     */
    public static function roles(array $claims): array
    {
        $r = $claims['roles'] ?? [];
        // nur Texte (verschachtelte Werte zählen nicht und lösen keine Warnung aus)
        $list = \is_array($r) ? array_filter($r, 'is_string') : (\is_string($r) ? preg_split('~[\s,]+~', $r) : []);

        return array_values(array_filter(array_map(static fn (string $v): string => strtolower(trim($v)), $list ?: []), static fn (string $v): bool => '' !== $v));
    }
}
