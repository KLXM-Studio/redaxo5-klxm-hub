<?php

namespace Klxm\Hub\Backend;

use Klxm\Hub\Accounts;
use Klxm\Hub\HubAddon;
use Klxm\Hub\Log;
use Klxm\Hub\Monitoring\Status;
use rex;
use rex_csrf_token;
use rex_formatter;
use rex_fragment;
use rex_url;
use rex_view;

/**
 * Backend → AddOns → Agentur Hub → Agentur-Konten: Liste der über den Hub angelegten Benutzer, lokal sperren/entsperren.
 * Löschen und alle weiteren Angaben über die Benutzerverwaltung (AddOn users).
 *
 * @internal
 */
final class AccountsPage
{
    private const string CSRF = 'klxm_hub_accounts';

    public static function run(): string
    {
        $out = self::action();
        $t = HubAddon::t(...);
        $csrf = rex_csrf_token::factory(self::CSRF)->getHiddenField();
        $rows = '';
        foreach (Accounts::all() as $a) {
            $active = 1 === (int) $a['status'];
            $hasPw = '' !== (string) $a['password'];
            $state = $active ? $t('state_active') : $t('state_locked');
            $rows .= '<tr>'
                . '<td><a href="' . rex_url::backendPage('users/users', ['user_id' => (int) $a['id']]) . '">' . rex_escape((string) ($a['name'] ?: $a['login'])) . '</a>'
                . '<br><small class="klxm-hub-muted">' . rex_escape((string) $a['login']) . '</small></td>'
                . '<td>' . ((int) $a['admin'] ? rex_escape($t('role_admin')) : rex_escape($t('role_redaktion_short'))) . '</td>'
                . '<td><span class="klxm-hub-state" data-state="' . ($active ? 'active' : 'locked') . '">' . rex_escape($state) . '</span>'
                . ($hasPw ? '<br><small class="klxm-hub-muted">' . rex_escape($t('state_local_password')) . '</small>' : '') . '</td>'
                . '<td>' . rex_escape(null === $a['last_login'] ? '–' : rex_formatter::intlDateTime((string) $a['last_login'])) . '</td>'
                . '<td><form method="post">' . $csrf . '<input type="hidden" name="klxm_hub_do" value="' . ($active ? 'lock' : 'unlock') . '">'
                . '<input type="hidden" name="user_id" value="' . (int) $a['id'] . '">'
                . '<button type="submit" class="btn btn-xs ' . ($active ? 'btn-delete" data-confirm="' . rex_escape($t('lock_confirm')) . '"' : 'btn-default"') . '>'
                . rex_escape($active ? $t('lock') : $t('unlock')) . '</button></form></td>'
                . '</tr>';
        }
        $table = '<table class="table table-hover klxm-hub-accounts"><thead><tr><th>' . rex_escape($t('col_account')) . '</th><th>' . rex_escape($t('col_role')) . '</th><th>'
            . rex_escape($t('col_state')) . '</th><th>' . rex_escape($t('col_last_login')) . '</th><th><span class="sr-only">' . rex_escape($t('col_actions')) . '</span></th></tr></thead><tbody>' . $rows . '</tbody></table>';
        $note = '<p>' . rex_escape($t('accounts_note')) . '</p>';
        if (0 === Status::localAdmins()) {
            $note .= rex_view::warning(rex_escape($t('warn_no_local_admin')));
        }
        $f = new rex_fragment();
        $f->setVar('title', $t('page_accounts'), false);
        $f->setVar('body', $note . ('' === $rows ? '<p>' . rex_escape($t('accounts_empty')) . '</p>' : ''), false);
        if ('' !== $rows) {
            $f->setVar('content', $table, false);
        }

        return $out . $f->parse('core/page/section.php');
    }

    private static function action(): string
    {
        $do = rex_post('klxm_hub_do', 'string', '');
        if ('' === $do) {
            return '';
        }
        if (!rex_csrf_token::factory(self::CSRF)->isValid()) {
            return rex_view::error(rex_escape(HubAddon::t('csrf')));
        }
        $id = rex_post('user_id', 'int', 0);
        if ($id <= 0 || !Accounts::isAgency($id) || $id === rex::requireUser()->getId()) {
            return rex_view::error(rex_escape(HubAddon::t('err_account')));
        }
        $lock = 'lock' === $do;
        Accounts::setStatus($id, !$lock);
        Log::write('info', $lock ? 'account-locked' : 'account-unlocked', ['user' => $id, 'by' => rex::requireUser()->getLogin()]);

        return rex_view::success(rex_escape(HubAddon::t($lock ? 'locked' : 'unlocked')));
    }
}
