<?php

namespace Klxm\Hub\Backend;

use Klxm\Hub\HubAddon;
use Klxm\Hub\Log;
use Klxm\Hub\Logo;
use Klxm\Hub\Monitoring\Status;
use Klxm\Hub\Oidc\Client;
use Klxm\Hub\Oidc\OidcException;
use Klxm\Hub\Settings;
use rex;
use rex_csrf_token;
use rex_fragment;
use rex_sql;
use rex_view;

/**
 * Backend → AddOns → Agentur Hub → Einstellungen: Anmeldung über den Hub und Überwachung (beides Standard aus).
 *
 * @internal
 */
final class SettingsPage
{
    private const string CSRF = 'klxm_hub_settings';

    public static function run(): string
    {
        $out = self::action();
        $s = Settings::oidc();
        $m = Settings::monitor();
        $t = HubAddon::t(...);
        $csrf = rex_csrf_token::factory(self::CSRF)->getHiddenField();

        $field = static fn (string $label, string $control, string $note = '', string $for = ''): string => '<div class="form-group">'
            . ('' !== $for ? '<label class="control-label" for="' . $for . '">' . $label . '</label>' : '<div class="control-label klxm-hub-label">' . $label . '</div>')
            . $control . ('' !== $note ? '<p class="help-block">' . $note . '</p>' : '') . '</div>';
        $check = static fn (string $name, bool $on, string $label): string => '<div class="checkbox"><label><input type="checkbox" name="' . $name . '" value="1"' . ($on ? ' checked' : '') . '> ' . $label . '</label></div>';
        $input = static fn (string $id, string $name, string $value, string $type = 'text', string $extra = ''): string => '<input class="form-control" type="' . $type . '" id="' . $id . '" name="' . $name . '" value="' . rex_escape($value) . '"' . $extra . '>';
        $section = static function (string $title, string $body, string $buttons = '', bool $collapsed = false): string {
            $f = new rex_fragment();
            $f->setVar('title', $title, false);
            $f->setVar('body', $body, false);
            if ('' !== $buttons) {
                $f->setVar('buttons', $buttons, false);
            }
            if ($collapsed) {
                $f->setVar('collapse', true);
                $f->setVar('collapsed', true);
            }

            return $f->parse('core/page/section.php');
        };

        // ---------------------------------------------------------------- Anmeldung
        $roles = '<option value="0">' . rex_escape($t('role_none')) . '</option>';
        foreach (rex_sql::factory()->getArray('SELECT id, name FROM ' . rex::getTable('user_role') . ' ORDER BY name') as $r) {
            $roles .= '<option value="' . (int) $r['id'] . '"' . ((int) $r['id'] === $s['role_redaktion'] ? ' selected' : '') . '>' . rex_escape((string) $r['name']) . '</option>';
        }
        $secretNote = $s['secret_from_env'] ? $t('secret_env') : ('' !== $s['client_secret'] ? $t('secret_saved') : $t('secret_missing'));
        $body = $field($t('oidc_enabled'), $check('oidc[enabled]', $s['enabled'], $t('oidc_enabled_label')), $t('oidc_enabled_note'))
            . $field($t('oidc_name'), $input('kh-name', 'oidc[name]', $s['name'], 'text', ' maxlength="60"'), $t('oidc_name_note'), 'kh-name')
            . $field($t('oidc_issuer'), $input('kh-iss', 'oidc[issuer]', $s['issuer'], 'url', ' placeholder="https://hub.example.org/hub" spellcheck="false"'), rex_escape($t('oidc_issuer_note')), 'kh-iss')
            . $field($t('oidc_client_id'), $input('kh-cid', 'oidc[client_id]', $s['client_id'], 'text', ' spellcheck="false" autocomplete="off"'), '', 'kh-cid')
            . $field($t('oidc_client_secret'), $input('kh-sec', 'oidc[client_secret]', '', 'password', ' autocomplete="new-password"' . ($s['secret_from_env'] ? ' disabled' : '')), rex_escape($secretNote), 'kh-sec')
            . $field($t('oidc_auth'), '<select class="form-control" id="kh-auth" name="oidc[auth]">'
                . '<option value="client_secret_basic"' . ('client_secret_basic' === $s['auth'] ? ' selected' : '') . '>client_secret_basic (' . rex_escape($t('recommended')) . ')</option>'
                . '<option value="client_secret_post"' . ('client_secret_post' === $s['auth'] ? ' selected' : '') . '>client_secret_post</option></select>', '', 'kh-auth')
            . $field($t('oidc_roles'), '<p class="klxm-hub-map"><code>admin</code> → ' . rex_escape($t('role_admin')) . '</p>'
                . '<p class="klxm-hub-map"><label for="kh-role"><code>redaktion</code> →</label> <select class="form-control klxm-hub-role" id="kh-role" name="oidc[role_redaktion]">' . $roles . '</select></p>', $t('oidc_roles_note'))
            . $field($t('oidc_jit'), $check('oidc[jit]', $s['jit'], $t('oidc_jit_label')), $t('oidc_jit_note'));
        $buttons = '<button type="submit" class="btn btn-save" name="klxm_hub_do" value="oidc">' . rex_escape($t('save')) . '</button>'
            . ('' !== $s['client_secret'] && !$s['secret_from_env'] ? ' <button type="submit" class="btn btn-delete" name="klxm_hub_forget" value="1" data-confirm="' . rex_escape($t('secret_forget_confirm')) . '">' . rex_escape($t('secret_forget')) . '</button>' : '');
        $out .= '<form method="post" class="klxm-hub-form" data-klxm-hub="oidc">' . $csrf . ''
            . $section($t('section_oidc'), $body, $buttons) . '</form>';

        // ---------------------------------------------------------------- Adressen für den Hub
        $addr = [
            $t('addr_redirect') => Client::redirectUri(),
            $t('addr_start') => Client::startUri(),
            $t('addr_status') => Client::statusUri(),
            $t('addr_logout') => Client::logoutUri(),
            $t('addr_instance') => rtrim(Settings::baseUrl(), '/') . '/index.php?rex-api-call=klxm_hub_instance',
        ];
        $rows = '';
        foreach ($addr as $label => $url) {
            $rows .= '<tr><th scope="row">' . rex_escape($label) . '</th><td><code class="klxm-hub-url">' . rex_escape((string) $url) . '</code></td></tr>';
        }
        // ohne feste Adresse der Website hängen Redirect-URI und Einstieg am Host der Anfrage (Host-Header)
        $baseWarn = Settings::baseUrlFixed() ? '' : rex_view::warning(rex_escape($t('warn_no_base_url')));
        $out .= $section($t('section_addresses'), '<p>' . rex_escape($t('addresses_note')) . '</p>' . $baseWarn
            . '<table class="table klxm-hub-addresses"><tbody>' . $rows . '</tbody></table>'
            . '<p class="help-block">' . rex_escape($t('addresses_instance_note')) . '</p>');

        // ---------------------------------------------------------------- Überwachung
        $keys = '';
        foreach ($m['keys'] as $k) {
            $keys .= ('' !== $k['label'] ? $k['label'] . ' ' : '') . $k['key'] . "\n";
        }
        $body = $field($t('monitor_enabled'), $check('monitor[enabled]', $m['enabled'], $t('monitor_enabled_label')), $t('monitor_enabled_note'))
            . $field($t('monitor_keys'), '<textarea class="form-control klxm-hub-keys" id="kh-keys" name="monitor[keys]" rows="3" spellcheck="false" placeholder="Agentur Hub ed25519:…">' . rex_escape($keys) . '</textarea>', $t('monitor_keys_note'), 'kh-keys')
            . $field($t('monitor_backup'), $input('kh-bk', 'monitor[backup_dir]', $m['backup_dir'], 'text', ' spellcheck="false" placeholder="../backups"'), $t('monitor_backup_note'), 'kh-bk');
        $buttons = '<button type="submit" class="btn btn-save" name="klxm_hub_do" value="monitor">' . rex_escape($t('save')) . '</button>';
        $out .= '<form method="post" class="klxm-hub-form" data-klxm-hub="monitor">' . $csrf . $section($t('section_monitor'), $body, $buttons) . '</form>';

        // ---------------------------------------------------------------- Vorschau der Antwort
        $preview = Status::build() + ['nonce' => '…'];
        $out .= $section($t('section_preview'), '<p>' . rex_escape($t('preview_note')) . '</p><pre class="klxm-hub-json">'
            . rex_escape((string) json_encode($preview, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)) . '</pre>', '', true);

        return $out;
    }

    private static function action(): string
    {
        $do = rex_post('klxm_hub_do', 'string', '');
        if ('' === $do && '' !== rex_post('klxm_hub_forget', 'string', '')) {
            $do = 'oidc';
        }
        if ('' === $do) {
            return '';
        }
        if (!rex_csrf_token::factory(self::CSRF)->isValid()) {
            return rex_view::error(rex_escape(HubAddon::t('csrf')));
        }
        $user = rex::requireUser()->getLogin();
        if ('monitor' === $do) {
            $in = rex_post('monitor', 'array', []);
            $err = Settings::saveMonitor(!empty($in['enabled']), (string) ($in['keys'] ?? ''), (string) ($in['backup_dir'] ?? ''));
            if (null !== $err) {
                return rex_view::error(rex_escape($err));
            }
            @unlink(Status::cacheFile());
            Log::write('info', 'settings-monitor', ['by' => $user, 'enabled' => (int) !empty($in['enabled'])]);

            return rex_view::success(rex_escape(HubAddon::t('saved_monitor')));
        }
        if ('oidc' !== $do) {
            return '';
        }
        if (rex_post('klxm_hub_forget', 'string', '')) {
            Settings::forgetSecret();
            Log::write('info', 'settings-oidc', ['by' => $user, 'secret' => 'removed']);

            return rex_view::success(rex_escape(HubAddon::t('secret_forgotten')));
        }
        $in = rex_post('oidc', 'array', []);
        $issuer = rtrim(trim((string) ($in['issuer'] ?? '')), '/');
        if ('' !== $issuer && !preg_match('~^https?://[^\s/?#]+(/[^\s?#]*)?$~', $issuer)) {
            return rex_view::error(rex_escape(HubAddon::t('err_issuer_format')));
        }
        Settings::saveOidc($in);
        Client::forgetCache($issuer);
        Log::write('info', 'settings-oidc', ['by' => $user, 'enabled' => (int) !empty($in['enabled'])]);
        $s = Settings::oidc();
        if (!$s['enabled']) {
            return rex_view::success(rex_escape(HubAddon::t('saved_oidc')));
        }
        if (!Settings::oidcReady($s)) {
            Settings::saveOidc(['enabled' => false] + $in);

            return rex_view::error(rex_escape(HubAddon::t('err_incomplete')));
        }
        try {
            Client::discovery($s['issuer'], true);
            Logo::refresh($s['issuer']);   // Logo des Anbieters (logo_uri) für den Anmelde-Link, optional
        } catch (OidcException $e) {
            Settings::saveOidc(['enabled' => false] + $in);
            Log::write('warning', 'settings-oidc', ['by' => $user, 'discovery' => $e->reason]);

            return rex_view::error(rex_escape(HubAddon::t('err_discovery_save', $e->reason)));
        }
        $warn = 0 === Status::localAdmins() ? rex_view::warning(rex_escape(HubAddon::t('warn_no_local_admin'))) : '';

        return rex_view::success(rex_escape(HubAddon::t('saved_oidc_ok'))) . $warn;
    }
}
