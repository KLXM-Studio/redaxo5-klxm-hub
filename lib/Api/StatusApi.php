<?php

namespace Klxm\Hub\Api;

use Klxm\Hub\Log;
use Klxm\Hub\Monitoring\Signature;
use Klxm\Hub\Monitoring\Status;
use Klxm\Hub\RateLimit;
use Klxm\Hub\Settings;
use rex;
use rex_api_function;
use rex_response;

/**
 * Signierte Status-Abfrage für den Hub (Protokoll status-v1) – Standard aus.
 *
 *   GET /index.php?rex-api-call=klxm_hub_status   nur mit gültig signierter Anfrage eines eingetragenen Schlüssels
 *
 * Reihenfolge der Prüfung wie in der Spezifikation: aus/kein Schlüssel → 404 · Rate-Limit je IP (30 in 10 Minuten) → 429 ·
 * Format, Zeitfenster (±300 s), Schlüssel, Signatur → 401 · erst danach Nonce merken (Wiederholung → 401) · 200 mit JSON.
 * Fehlerantworten ohne Gründe; der Grund steht im Systemprotokoll („klxm_hub: monitor-denied reason=…“).
 * Host aus der Anfrage (hinter einem Proxy: X-Forwarded-Host nur von vertrauenswürdigen Proxys, Request::setTrustedProxies),
 * Pfad mit Query aus REQUEST_URI.
 */
final class StatusApi extends rex_api_function
{
    protected $published = true;

    private const int MAX_REQUESTS = 30;
    private const int WINDOW = 600;

    public function execute()
    {
        $s = Settings::monitor();
        if (!$s['enabled'] || !$s['keys']) {
            self::send(['error' => 'not_found'], rex_response::HTTP_NOT_FOUND);
        }
        $ipKey = RateLimit::ip('monitor');
        if (RateLimit::tooMany($ipKey, self::MAX_REQUESTS, self::WINDOW)) {
            Log::write('warning', 'monitor-denied', ['reason' => 'rate_limit']);
            self::send(['error' => 'rate_limited'], '429 Too Many Requests');
        }
        RateLimit::hit($ipKey);

        $request = rex::getRequest();
        $h = [];
        foreach (['x-status-key', 'x-status-timestamp', 'x-status-nonce', 'x-status-signature'] as $k) {
            $h[$k] = (string) $request->headers->get($k, '');
        }
        $keys = array_values(array_filter(array_map(static fn (array $k): ?string => Signature::parseKey($k['key']), $s['keys'])));
        $reason = Signature::verify($h, $request->getMethod(), strtolower($request->getHttpHost()), (string) $request->server->get('REQUEST_URI', '/'), $keys,
            self::seenNonce(...));
        if (null !== $reason) {
            Log::write('warning', 'monitor-denied', ['reason' => $reason]);
            self::send(['error' => 'unauthorized'], rex_response::HTTP_UNAUTHORIZED);
        }
        self::send(Status::collect($h['x-status-nonce']), rex_response::HTTP_OK);
    }

    protected function requiresCsrfProtection()
    {
        return false;
    }

    /** Nonce schon verwendet? Sonst merken ({@see Signature::NONCE_KEEP}) – nur nach gültiger Signatur aufgerufen */
    public static function seenNonce(string $kid, string $nonce): bool
    {
        $key = 'mon-nonce:' . $kid . ':' . $nonce;
        if (RateLimit::count($key, Signature::NONCE_KEEP) > 0) {
            return true;
        }
        RateLimit::hit($key);

        return false;
    }

    /** @param array<string, mixed> $data */
    public static function send(array $data, string $status): never
    {
        rex_response::cleanOutputBuffers();
        rex_response::setStatus($status);
        rex_response::setHeader('X-Robots-Tag', 'noindex');
        rex_response::sendCacheControl('no-store');
        rex_response::sendContent((string) json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), 'application/json');
        exit;
    }
}
