<?php

namespace Klxm\Hub\Oidc;

/**
 * Anmeldung über den Anbieter abgebrochen. $reason ist der kurze Grund fürs Protokoll (z. B. „state“, „iss“, „token:aud“),
 * die Nachricht ist für Menschen und verrät keine Einzelheiten.
 */
final class OidcException extends \RuntimeException
{
    public function __construct(public readonly string $reason, string $message = '')
    {
        parent::__construct($message);
    }
}
