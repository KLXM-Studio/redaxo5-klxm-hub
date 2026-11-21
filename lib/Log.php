<?php

namespace Klxm\Hub;

use rex_logger;

/**
 * Protokoll im Systemprotokoll von REDAXO (System → Log-Dateien → REDAXO, redaxo/data/log/system.log) – eine Zeile je
 * Ereignis, gleich aufgebaut, damit fail2ban & Co. sie auswerten können:
 *
 *   klxm_hub: login-denied reason=state ip=203.0.113.7
 *   klxm_hub: login-ok user=12 created=0 ip=…
 *   klxm_hub: monitor-denied reason=signature ip=…
 *
 * Keine Geheimnisse, keine Tokens, keine Codes im Protokoll.
 */
final class Log
{
    /** @var list<array{0: string, 1: string}>|null Selbsttest: sammeln statt schreiben */
    public static ?array $memory = null;

    /** @param array<string, string|int> $ctx */
    public static function write(string $level, string $event, array $ctx = []): void
    {
        $ctx += ['ip' => RateLimit::clientIp()];
        $line = 'klxm_hub: ' . $event;
        foreach ($ctx as $k => $v) {
            $line .= ' ' . $k . '=' . preg_replace('~[^\w.:@/+-]~u', '_', mb_substr((string) $v, 0, 120));
        }
        if (null !== self::$memory) {
            self::$memory[] = [$level, $line];

            return;
        }
        rex_logger::factory()->log($level, $line);
    }
}
