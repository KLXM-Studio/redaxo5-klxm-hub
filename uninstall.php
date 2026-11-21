<?php

/**
 * Deinstallation: Tabellen des AddOns entfernen. Agentur-Benutzer bleiben in der Benutzerverwaltung (ohne Passwort,
 * also ohne Anmeldung) – löschen bei Bedarf über Benutzer.
 *
 * @var rex_addon $this
 */

rex_sql_table::get(rex::getTable('klxm_hub_identity'))->drop();
rex_sql_table::get(rex::getTable('klxm_hub_hit'))->drop();
