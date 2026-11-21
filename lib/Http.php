<?php

namespace Klxm\Hub;

use Klxm\Hub\Http\PinnedSocket;
use rex;
use rex_socket_proxy;

/**
 * Abrufe beim Anbieter (Discovery, JWKS, Token, Logo) über rex_socket: höchstens 10 Sekunden je Lesevorgang und
 * 15 Sekunden insgesamt, keine Weiterleitungen, Antworten bis 512 KB. Für den Selbsttest ersetzt Http::$transport die Abrufe.
 *
 * Nur https (http nur mit KLXM_HUB_ALLOW_HTTP=1, für Tests im lokalen Netz). Schutz vor SSRF: Ziele in privaten, lokalen
 * und reservierten Netzen (127/8, 10/8, 172.16/12, 192.168/16, 169.254/16, 100.64/10, ::1, fc00::/7, fe80::/10, IPv4 in
 * IPv6 …) werden abgewiesen – geprüft werden alle aufgelösten Adressen, verbunden wird genau mit der geprüften
 * ({@see PinnedSocket}, TLS-Prüfung weiter gegen den Hostnamen; kein DNS-Rebinding). Ausnahme: Umgebungsvariable
 * KLXM_HUB_ALLOW_PRIVATE_NETWORK=1 (Hub im eigenen Netz). Mit einem ausgehenden Proxy (System → socket_proxy) prüft das
 * AddOn die Adressen des Ziels ebenso, die Verbindung baut aber der Proxy auf.
 */
final class Http
{
    public const int MAX_BYTES = 524288;
    public const int TIMEOUT = 10;
    public const int MAX_DURATION = 15;

    /** @var null|callable(string $method, string $url, array<string, string> $headers, ?string $body): array{status: int, body: string} */
    public static $transport = null;

    /**
     * @param array<string, string> $headers
     * @throws \RuntimeException
     * @return array{status: int, body: string}
     */
    public static function request(string $method, string $url, array $headers = [], ?string $body = null): array
    {
        if (null !== self::$transport) {
            return (self::$transport)($method, $url, $headers, $body);
        }
        $p = parse_url($url);
        $scheme = strtolower((string) ($p['scheme'] ?? ''));
        $host = (string) ($p['host'] ?? '');
        if (!\in_array($scheme, ['https', 'http'], true) || '' === $host || isset($p['user']) || isset($p['pass'])) {
            throw new \RuntimeException('invalid url');
        }
        if ('http' === $scheme && !self::allowHttp()) {
            throw new \RuntimeException('insecure url');
        }
        $ssl = 'https' === $scheme;
        $port = (int) ($p['port'] ?? ($ssl ? 443 : 80));
        $path = ($p['path'] ?? '/') . (isset($p['query']) ? '?' . $p['query'] : '');
        $ip = self::resolve($host, self::allowPrivateNetwork());

        $proxy = rex::getProperty('socket_proxy');
        $socket = $proxy ? rex_socket_proxy::factoryUrl((string) $proxy)->setDestination($host, $port, $ssl) : PinnedSocket::pinned($host, $port, $ssl, $ip);
        $socket->setPath($path)->setTimeout(self::TIMEOUT)->followRedirects(false);
        // rex_socket setzt Host ohne Port – bei abweichendem Port gehört er dazu (RFC 9110, 7.2)
        $socket->addHeader('Host', $host . ($port !== ($ssl ? 443 : 80) ? ':' . $port : ''));
        foreach ($headers + ['Accept' => 'application/json', 'User-Agent' => 'REDAXO klxm_hub'] as $k => $v) {
            $socket->addHeader($k, $v);
        }
        $response = 'POST' === strtoupper($method) ? $socket->doPost($body ?? '') : $socket->doGet();
        $out = '';
        $start = microtime(true);
        while (false !== ($buf = $response->getBufferedBody(8192))) {
            $out .= $buf;
            if (\strlen($out) > self::MAX_BYTES) {
                throw new \RuntimeException('response too large');
            }
            if (microtime(true) - $start > self::MAX_DURATION) {
                throw new \RuntimeException('timeout');
            }
        }

        return ['status' => (int) $response->getStatusCode(), 'body' => $out];
    }

    /** Ziele in privaten Netzen erlaubt? (nur ausdrücklich per Umgebungsvariable) */
    public static function allowPrivateNetwork(): bool
    {
        return Env::flag('KLXM_HUB_ALLOW_PRIVATE_NETWORK');
    }

    /** Anbieter ohne https erlaubt? (nur ausdrücklich per Umgebungsvariable, für Tests) */
    public static function allowHttp(): bool
    {
        return Env::flag('KLXM_HUB_ALLOW_HTTP');
    }

    /**
     * Hostnamen auflösen; alle Adressen müssen öffentlich sein (außer $allowPrivate). Rückgabe: die Adresse, mit der
     * verbunden wird (IPv4 bevorzugt).
     *
     * @throws \RuntimeException „… is blocked“ bzw. „could not resolve …“
     */
    public static function resolve(string $host, bool $allowPrivate): string
    {
        $h = trim($host, '[]');
        if (false !== filter_var($h, FILTER_VALIDATE_IP)) {
            $ips = [$h];
        } else {
            $ips = gethostbynamel($h) ?: [];
            foreach (@dns_get_record($h, DNS_AAAA) ?: [] as $r) {
                if (isset($r['ipv6'])) {
                    $ips[] = (string) $r['ipv6'];
                }
            }
        }
        if (!$ips) {
            throw new \RuntimeException('could not resolve host');
        }
        if (!$allowPrivate) {
            foreach ($ips as $ip) {
                if (!self::isPublicIp($ip)) {
                    throw new \RuntimeException('host "' . $h . '" is blocked (private network)');
                }
            }
        }

        return $ips[0];
    }

    /**
     * Öffentliche (global erreichbare) Adresse? Nein für private, lokale, reservierte und Dokumentationsnetze, auch als
     * IPv4 in IPv6 (::ffff:a.b.c.d, ::a.b.c.d, 64:ff9b::a.b.c.d) verpackt.
     */
    public static function isPublicIp(string $ip): bool
    {
        $bin = @inet_pton($ip);
        if (false === $bin) {
            return false;
        }
        if (16 === \strlen($bin)) {
            $v4 = null;
            if (str_starts_with($bin, str_repeat("\0", 10) . "\xff\xff") || str_starts_with($bin, str_repeat("\0", 12))) {
                $v4 = substr($bin, 12);   // IPv4-mapped / -compatible
            } elseif (str_starts_with($bin, "\x00\x64\xff\x9b" . str_repeat("\0", 8))) {
                $v4 = substr($bin, 12);   // NAT64
            } elseif (str_starts_with($bin, "\x20\x02")) {
                $v4 = substr($bin, 2, 4);   // 6to4
            }
            if (null !== $v4) {
                return self::isPublicIp((string) inet_ntop($v4));
            }
            $first = \ord($bin[0]);
            // fc00::/7 (ULA), fe80::/10 (link-local), fec0::/10 (site-local), ff00::/8 (Multicast)
            if (0xFC === ($first & 0xFE) || 0xFF === $first || (0xFE === $first && 0x80 === (\ord($bin[1]) & 0x80))) {
                return false;
            }
        } else {
            $n = unpack('N', $bin)[1];
            // 100.64.0.0/10 (CGNAT), 0.0.0.0/8, 192.0.0.0/24, 198.18.0.0/15 – zusätzlich zur Prüfung von PHP
            foreach ([[0x64400000, 10], [0x00000000, 8], [0xC0000000, 24], [0xC6120000, 15]] as [$net, $bits]) {
                $mask = (-1 << (32 - $bits)) & 0xFFFFFFFF;
                if (($n & $mask) === $net) {
                    return false;
                }
            }
        }

        return false !== filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_GLOBAL_RANGE | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
    }
}
