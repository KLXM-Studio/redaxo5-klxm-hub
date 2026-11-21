<?php

namespace Klxm\Hub\Api;

use Klxm\Hub\InstanceInfo;
use rex_api_function;

/**
 * Selbstauskunft klxm-instance-v1 ohne Umschreibregel: GET /index.php?rex-api-call=klxm_hub_instance
 * (gleicher Inhalt wie /.well-known/klxm-studio, {@see InstanceInfo}).
 */
final class InstanceApi extends rex_api_function
{
    protected $published = true;

    public function execute()
    {
        InstanceInfo::send();
    }

    protected function requiresCsrfProtection()
    {
        return false;
    }
}
