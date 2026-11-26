<?php

namespace Klxm\Hub\Api;

use Klxm\Hub\Enroll;
use rex_api_function;

/**
 * Verbindung per Einmal-Code: POST /index.php?rex-api-call=klxm_hub_enroll (JSON) – nur mit offenem Code, {@see Enroll}.
 */
final class EnrollApi extends rex_api_function
{
    protected $published = true;

    public function execute()
    {
        if ('POST' !== strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'))) {
            StatusApi::send(['error' => 'method_not_allowed'], '405 Method Not Allowed');
        }
        $in = json_decode((string) file_get_contents('php://input'), true);
        [$status, $body] = Enroll::handle(\is_array($in) ? $in : []);
        StatusApi::send($body, match ($status) { 200 => '200 OK', 400 => '400 Bad Request', 401 => '401 Unauthorized', 429 => '429 Too Many Requests', default => '500 Internal Server Error' });
    }

    protected function requiresCsrfProtection()
    {
        return false;
    }
}
