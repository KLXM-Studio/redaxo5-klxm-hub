<?php

namespace Klxm\Hub\ExtensionPoint;

use rex_extension_point;

/**
 * Erweiterungspunkt KLXM_HUB_STATUS: Antwort der Status-Abfrage (status-v1) ergänzen, bevor sie zwischengespeichert
 * wird (60 Sekunden) – z. B. eigene Prüfungen als Meldungen, die letzte Sicherung eines Backup-Werkzeugs:
 *
 *     rex_extension::register('KLXM_HUB_STATUS', static function (rex_extension_point $ep): array {
 *         $status = $ep->getSubject();
 *         $status['backup']['offsite_at'] = date('c', MyBackup::lastUpload());
 *         if ($ep instanceof Klxm\Hub\ExtensionPoint\HubStatus) {
 *             $ep->warning('Speicherplatz fast voll');      // zählt in health mit
 *         }
 *         return $status;
 *     });
 *
 * Keine Inhalte, keine Konten, keine Personendaten, keine Geheimnisse, keine Serverpfade.
 * Gleich wie HubStatus in der Fassung für REDAXO 6 (dort mit dem Klassennamen als Name).
 */
final class HubStatus extends rex_extension_point
{
    public const string NAME = 'KLXM_HUB_STATUS';

    /** @var list<array{level: string, text: string, category?: string}> */
    public array $messages = [];

    /** @param array<string, mixed> $status */
    public function __construct(array $status)
    {
        parent::__construct(self::NAME, $status);
    }

    /** Fehler (rot). $category: technical (Standard), setup oder editorial – siehe Protokoll status-v1, 4.1 */
    public function error(string $text, string $category = 'technical'): void
    {
        $this->messages[] = ['level' => 'error', 'text' => $text, 'category' => $category];
    }

    /** Hinweis (gelb). $category wie bei {@see self::error()} */
    public function warning(string $text, string $category = 'technical'): void
    {
        $this->messages[] = ['level' => 'warning', 'text' => $text, 'category' => $category];
    }
}
