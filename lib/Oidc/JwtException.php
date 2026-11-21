<?php

namespace Klxm\Hub\Oidc;

/** Prüfung eines JWT fehlgeschlagen – die Nachricht ist ein kurzer Grund (format, alg, signature, unknown_kid …). */
final class JwtException extends \RuntimeException {}
