<?php

namespace Klxm\Hub;

use Klxm\Hub\Api\InstanceApi;
use Klxm\Hub\Api\LoginApi;
use Klxm\Hub\Api\StatusApi;
use Klxm\Hub\Oidc\Client;
use rex;
use rex_addon;
use rex_api_function;
use rex_backend_login;
use rex_be_controller;
use rex_extension;
use rex_extension_point;
use rex_i18n;
use rex_response;
use rex_url;
use rex_user_session;
use rex_view;

/**
 * Agentur Hub für REDAXO 5: Anmeldung im Backend über den Hub (OpenID Connect, {@see Api\LoginApi}), signierte
 * Status-Abfrage für die Überwachung ({@see Api\StatusApi}) und Selbstauskunft ({@see InstanceInfo}). Alles ist aus,
 * bis es unter AddOns → Agentur Hub eingeschaltet wird.
 *
 * Gleich aufgebaut wie die Fassung für REDAXO 6 (KLXM-Studio/redaxo-klxm-hub), damit Korrekturen übertragbar sind;
 * dort heißt diese Klasse ebenfalls HubAddon (dort die Addon-Klasse, hier die Sammlung für boot.php).
 */
final class HubAddon
{
    public const string NAME = 'klxm_hub';

    /** Übersetzung mit Präfix klxm_hub_ */
    public static function t(string $key, string|int ...$replacements): string
    {
        return rex_i18n::msg(self::NAME . '_' . $key, ...$replacements);
    }

    public static function addon(): rex_addon
    {
        return rex_addon::get(self::NAME);
    }

    /** Tabellenname mit Präfix der Installation */
    public static function table(string $name): string
    {
        return rex::getTable(self::NAME . '_' . $name);
    }

    /** Aufgerufen aus boot.php */
    public static function boot(rex_addon $addon): void
    {
        rex_api_function::register('klxm_hub', LoginApi::class);
        rex_api_function::register('klxm_hub_status', StatusApi::class);
        rex_api_function::register('klxm_hub_instance', InstanceApi::class);

        // Zuordnung entfernen, wenn der Benutzer im Core gelöscht wird
        rex_extension::register('USER_DELETED', static function (rex_extension_point $ep): void {
            Accounts::forget((int) $ep->getParam('id'));
        });

        if (rex::isSetup() || \PHP_SAPI === 'cli') {
            return;
        }

        if (!rex::isBackend()) {
            // Selbstauskunft unter /.well-known/klxm-studio (sofern die Anfrage index.php erreicht, z. B. mit yrewrite)
            InstanceInfo::serveWellKnown();

            return;
        }

        self::denyAgencyPasskey();

        $page = rex_request('page', 'string', '');
        if (str_starts_with($page, self::NAME)) {
            rex_view::addCssFile($addon->getAssetsUrl('klxm_hub.css'));
        }

        // Anmeldeseite: Link „Mit Agentur Hub anmelden“ (nur wenn eingeschaltet und vollständig eingerichtet)
        if (!rex::getUser() && Settings::oidcReady()) {
            rex_view::addCssFile($addon->getAssetsUrl('klxm_hub.css'));
            rex_extension::register('OUTPUT_FILTER', static function (rex_extension_point $ep): string {
                $html = (string) $ep->getSubject();
                if ('login' !== rex_be_controller::getCurrentPage()) {
                    return $html;
                }

                return self::injectButton($html);
            });
        }
    }

    /**
     * Agentur-Konten (ohne lokales Passwort) melden sich nur über den Hub an: Eine Sitzung, die per Passkey entstanden
     * ist, wird sofort beendet – sonst wirkte ein Entzug im Hub nicht, solange das Konto lokal einen Passkey hat.
     * Bekommt ein Agentur-Konto lokal ein Passwort, ist es ein lokales Konto (wie in der Fassung für REDAXO 6).
     */
    private static function denyAgencyPasskey(): void
    {
        $login = rex::getProperty('login');
        $user = rex::getUser();
        if (!$user || !$login instanceof rex_backend_login || null === $login->getPasskey() || '' !== (string) $user->getValue('password')
            || !Accounts::isAgency($user->getId())) {
            return;
        }
        Log::write('warning', 'login-denied', ['reason' => 'passkey', 'user' => $user->getId()]);
        rex_user_session::getInstance()->clearCurrentSession();
        rex_backend_login::deleteSession();
        rex_response::sendRedirect(rex_url::backendController(['rex_logged_out' => 1], false));
    }

    /**
     * Link in die Anmeldeseite einfügen – im Fuß des Abschnitts im Formular #rex-form-login. Der Core hat dort keinen
     * Erweiterungspunkt; fehlt das Formular, bleibt die Seite unverändert.
     */
    public static function injectButton(string $html): string
    {
        $form = strpos($html, 'id="rex-form-login"');
        if (false === $form) {
            return $html;
        }
        // im Fuß des Abschnitts unter dem Login-Knopf (gleiche Abstände), sonst am Ende des Abschnitts
        $section = strpos($html, '</section>', $form);
        $footer = strpos($html, '</footer>', $form);
        $end = false !== $footer && (false === $section || $footer < $section) ? $footer : $section;
        if (false === $end) {
            return $html;
        }
        $name = Settings::oidc()['name'];
        // dezent unter dem Formular: Trennlinie, kleiner Link mit Logo des Anbieters (Passkey/Passwort bleiben vorn)
        $logo = Logo::svg() ?? '<i class="rex-icon fa-sign-in" aria-hidden="true"></i>';
        $button = '<div class="klxm-hub-login">'
            . '<a class="klxm-hub-login-link" href="' . rex_escape(Client::startLink()) . '">' . $logo
            . '<span>' . rex_escape(self::t('login_button', $name)) . '</span></a>'
            . '<p class="klxm-hub-login-note">' . rex_escape(self::t('login_note')) . '</p>'
            . '</div>';

        return substr($html, 0, $end) . $button . substr($html, $end);
    }
}
