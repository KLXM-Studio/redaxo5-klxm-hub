<?php

namespace Klxm\Hub\ExtensionPoint;

use rex_extension_point;

/**
 * Erweiterungspunkt KLXM_HUB_USER_MAPPING: Rechte eines Agentur-Kontos bei der Anmeldung über den Hub anpassen.
 * Subject: ['admin' => bool, 'roles' => list<int>] (Rollen-IDs aus rex_user_role) oder null = Anmeldung ablehnen.
 * Parameter: claims (geprüftes ID-Token), hub_roles (Rollen aus dem Claim „roles“, klein geschrieben).
 *
 *     rex_extension::register('KLXM_HUB_USER_MAPPING', static function (rex_extension_point $ep): ?array {
 *         if (in_array('technik', $ep->getParam('hub_roles'), true)) {
 *             return ['admin' => false, 'roles' => [3]];
 *         }
 *         return $ep->getSubject();
 *     });
 *
 * Gleich wie HubUserMapping in der Fassung für REDAXO 6 (dort mit dem Klassennamen als Name).
 */
final class HubUserMapping extends rex_extension_point
{
    public const string NAME = 'KLXM_HUB_USER_MAPPING';

    /**
     * @param array{admin: bool, roles: list<int>}|null $mapping
     * @param array<mixed> $claims
     * @param list<string> $hubRoles
     */
    public function __construct(?array $mapping, public readonly array $claims, public readonly array $hubRoles)
    {
        parent::__construct(self::NAME, $mapping, ['claims' => $claims, 'hub_roles' => $hubRoles]);
    }
}
