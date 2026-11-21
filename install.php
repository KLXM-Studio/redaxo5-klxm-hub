<?php

/**
 * Tabellen des AddOns (gleich aufgebaut wie in der Fassung für REDAXO 6).
 *
 * @var rex_addon $this
 */

// Zuordnung Anbieter-Konto (iss + sub) → REDAXO-Benutzer
rex_sql_table::get(rex::getTable('klxm_hub_identity'))
    ->ensurePrimaryIdColumn()
    ->ensureColumn(new rex_sql_column('issuer', 'varchar(191)'))
    ->ensureColumn(new rex_sql_column('sub', 'varchar(191)'))
    // SHA-256 von issuer + "\n" + sub: eindeutig und unabhängig von der Sortierung der Datenbank (sub ist case-sensitiv)
    ->ensureColumn(new rex_sql_column('subject_hash', 'char(64)'))
    ->ensureColumn(new rex_sql_column('user_id', 'int(10) unsigned'))
    ->ensureColumn(new rex_sql_column('email', 'varchar(191)', true))
    ->ensureColumn(new rex_sql_column('created', 'datetime', true))
    ->ensureColumn(new rex_sql_column('last_login', 'datetime', true))
    ->ensureIndex(new rex_sql_index('subject_hash', ['subject_hash'], rex_sql_index::UNIQUE))
    ->ensureIndex(new rex_sql_index('user_id', ['user_id']))
    ->ensure();

// Rate-Limit und gesehene Nonces (Schlüssel als SHA-256)
rex_sql_table::get(rex::getTable('klxm_hub_hit'))
    ->ensurePrimaryIdColumn()
    ->ensureColumn(new rex_sql_column('k', 'char(64)'))
    ->ensureColumn(new rex_sql_column('t', 'int(10) unsigned'))
    ->ensureIndex(new rex_sql_index('k_t', ['k', 't']))
    ->ensure();
