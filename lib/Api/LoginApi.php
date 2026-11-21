<?php

namespace Klxm\Hub\Api;

use Klxm\Hub\Accounts;
use Klxm\Hub\HubAddon;
use Klxm\Hub\Log;
use Klxm\Hub\Oidc\Client;
use Klxm\Hub\Oidc\OidcException;
use Klxm\Hub\RateLimit;
use Klxm\Hub\Settings;
use rex;
use rex_api_function;
use rex_api_result;
use rex_backend_login;
use rex_login;
use rex_response;
use rex_sql;
use rex_url;
use rex_user_session;

/**
 * Anmeldung im Backend über den Hub (OpenID Connect).
 *
 *   …/redaxo/index.php?rex-api-call=klxm_hub&step=start      Link auf der Anmeldeseite bzw. Einstieg vom Hub
 *                                                             (optional &iss=<Issuer>&login_hint=<E-Mail>)
 *   …/redaxo/index.php?rex-api-call=klxm_hub&step=callback   Rückkehr vom Hub (Redirect-URI)
 *
 * Öffentlich (vor der Anmeldung erreichbar) und ohne CSRF-Token des Cores – den Schutz übernimmt der state, der an die
 * Backend-Sitzung gebunden und nur einmal verwendbar ist. Fehler erscheinen als Meldung auf der Anmeldeseite (HTTP 400),
 * ohne Einzelheiten; der Grund steht im Systemprotokoll. Ausgeschaltet → 404.
 *
 * REDAXO 5 ruft API-Funktionen im Backend ohne Anmeldung auf der Seite „login“ auf (backend.php, nach PAGE_CHECKED);
 * die Meldung landet über $rexUserLoginmessage auf der Anmeldeseite.
 */
final class LoginApi extends rex_api_function
{
    protected $published = true;

    /** Rate-Limit je IP: Anfragen bzw. Fehlversuche in 10 Minuten */
    private const int MAX_REQUESTS = 30;
    private const int MAX_FAILURES = 10;
    private const int WINDOW = 600;

    /** Sitzungsvariable: Anmeldung kam über den Hub (für die Sperre von Passkeys bei Agentur-Konten) */
    public const string SESSION_VIA_HUB = 'klxm_hub_via';

    public function execute()
    {
        $s = Settings::oidc();
        $step = rex_get('step', 'string', '');
        if (!rex::isBackend() || !Settings::oidcReady($s) || !\in_array($step, ['start', 'callback'], true)) {
            self::notFound();
        }
        if (RateLimit::tooMany(RateLimit::ip('login'), self::MAX_REQUESTS, self::WINDOW) || RateLimit::tooMany(RateLimit::ip('login-fail'), self::MAX_FAILURES, self::WINDOW)) {
            Log::write('warning', 'login-denied', ['reason' => 'rate_limit']);

            return self::show(HubAddon::t('err_rate_limit'), '429 Too Many Requests');
        }
        RateLimit::hit(RateLimit::ip('login'));
        // Weiterleitungen tragen state und Redirect-URI – nie zwischenspeichern (auch nicht in Proxys)
        rex_response::setHeader('Cache-Control', 'no-store');

        try {
            if ('start' === $step) {
                self::start($s);
            }
            self::callback($s);
        } catch (OidcException $e) {
            RateLimit::hit(RateLimit::ip('login-fail'));
            Log::write('warning', 'login-denied', ['reason' => $e->reason]);

            return self::show($e->getMessage() ?: HubAddon::t('err_generic'));
        }
    }

    /** Nur GET (Weiterleitungen) – CSRF-Schutz übernimmt der state */
    protected function requiresCsrfProtection()
    {
        return false;
    }

    /** @param array{name: string, issuer: string, client_id: string} $s */
    private static function start(array $s): never
    {
        // Bereits angemeldet: direkt ins Backend
        if (rex::getUser()) {
            rex_response::sendRedirect(rex_url::backendController([], false));
        }
        $iss = rex_get('iss', 'string', '');
        if ('' !== $iss && !hash_equals($s['issuer'], rtrim($iss, '/'))) {
            throw new OidcException('start:iss', HubAddon::t('err_generic'));
        }
        $hint = rex_get('login_hint', 'string', '');
        $hint = filter_var($hint, FILTER_VALIDATE_EMAIL) ? $hint : '';
        rex_response::sendRedirect(Client::begin($s, $hint));
    }

    /** @param array{enabled: bool, name: string, issuer: string, client_id: string, client_secret: string, auth: string, jit: bool, role_redaktion: int} $s */
    private static function callback(array $s): never
    {
        $error = rex_get('error', 'string', '');
        $state = rex_get('state', 'string', '');
        $pend = '' !== $state ? Client::takeState($state) : null;
        if ('' !== $error) {
            throw new OidcException('provider:' . preg_replace('~[^\w.-]~', '', mb_substr($error, 0, 40)), HubAddon::t('err_provider_cancelled'));
        }
        if (null === $pend || !hash_equals((string) ($pend['iss'] ?? ''), $s['issuer'])) {
            throw new OidcException('state', HubAddon::t('err_state'));
        }
        // RFC 9207: iss in der Antwort muss der eingestellte Issuer sein (Pflicht, wenn der Anbieter ihn ankündigt)
        $iss = rex_get('iss', 'string', '');
        $disc = Client::discovery($s['issuer']);
        if ('' !== $iss ? !hash_equals($s['issuer'], rtrim($iss, '/')) : !empty($disc['authorization_response_iss_parameter_supported'])) {
            throw new OidcException('iss', HubAddon::t('err_generic'));
        }
        $res = Client::finish($s, $pend, rex_get('code', 'string', ''));
        $claims = $res['claims'];
        if (!Client::strongAmr($claims)) {
            throw new OidcException('mfa', HubAddon::t('err_mfa'));
        }
        $acc = Accounts::resolve($claims, $s);
        self::login($acc['user_id']);
        Log::write('info', 'login-ok', ['user' => $acc['user_id'], 'created' => (int) $acc['created']]);
        rex_response::sendRedirect(rex_url::backendController([], false));
    }

    /**
     * Benutzer in der Backend-Sitzung anmelden – wie die Anmeldung per Passkey im Core (rex_backend_login::checkLogin):
     * Sitzung erneuern, Benutzer-ID ohne Passwort-Hash, Start/Aktivität setzen, Sitzung in rex_user_session eintragen,
     * Anmeldezeit und session_id am Benutzer. Der Core bietet dafür keine öffentliche Methode.
     */
    private static function login(int $userId): void
    {
        $login = rex::getProperty('login');
        if (!$login instanceof rex_backend_login) {
            $login = new rex_backend_login();
        }
        rex_login::regenerateSessionId();
        Client::forgetPending();   // weitere offene Anmeldungen dieser Sitzung verfallen
        $login->setSessionVar(rex_login::SESSION_USER_ID, $userId);
        $login->setSessionVar(rex_login::SESSION_PASSWORD, null);
        $login->setSessionVar(rex_login::SESSION_IMPERSONATOR, null);
        $login->setSessionVar(rex_login::SESSION_START_TIME, time());
        $login->setSessionVar(rex_login::SESSION_LAST_ACTIVITY, time());
        // „Eingeloggt bleiben“ nie über den Hub (Konstante erst ab REDAXO 5.18)
        $login->setSessionVar(\defined(rex_backend_login::class . '::SESSION_STAY_LOGGED_IN') ? rex_backend_login::SESSION_STAY_LOGGED_IN : 'stay_logged_in', false);
        $login->setSessionVar(self::SESSION_VIA_HUB, true);
        rex_user_session::getInstance()->storeCurrentSession($login);
        rex_user_session::clearExpiredSessions();
        rex_sql::factory()->setQuery('UPDATE ' . rex::getTable('user') . ' SET login_tries = 0, lasttrydate = ?, lastlogin = ?, session_id = ? WHERE id = ? LIMIT 1',
            [rex_sql::datetime(), rex_sql::datetime(), (string) session_id(), $userId]);
    }

    /** Aus bzw. unbekannter Schritt: schlicht 404 */
    private static function notFound(): never
    {
        rex_response::cleanOutputBuffers();
        rex_response::setStatus(rex_response::HTTP_NOT_FOUND);
        rex_response::sendCacheControl('no-store');
        rex_response::sendContent('Not found', 'text/plain; charset=utf-8');
        exit;
    }

    /** Meldung auf der Anmeldeseite des Backends */
    private static function show(string $message, string $status = rex_response::HTTP_BAD_REQUEST): rex_api_result
    {
        rex_response::setStatus($status);
        $GLOBALS['rexUserLoginmessage'] = $message;

        return new rex_api_result(false);
    }
}
