<?php

namespace Klxm\Hub\Http;

use Klxm\Hub\Http;
use rex_socket;
use rex_socket_exception;
use rex_socket_response;

/**
 * rex_socket mit fester Zieladresse: verbindet genau mit der vorher geprüften IP ({@see Http::resolve()}), Host-Kopfzeile
 * und TLS-Prüfung (SNI, Zertifikat, Hostname) bleiben beim Hostnamen. Die Antwort wird mit Obergrenzen gelesen
 * (Kopf + Inhalt höchstens 512 KB + 16 KB, höchstens 15 Sekunden) und erst dann an rex_socket_response übergeben –
 * ein Anbieter kann so weder den Speicher füllen noch die Anfrage beliebig lange offen halten.
 *
 * @internal
 */
final class PinnedSocket extends rex_socket
{
    private string $ip = '';

    public static function pinned(string $host, int $port, bool $ssl, string $ip): self
    {
        $s = new self($host, $port, $ssl);
        $s->ip = $ip;

        return $s;
    }

    protected function openConnection()
    {
        $addr = str_contains($this->ip, ':') ? '[' . $this->ip . ']' : $this->ip;
        $target = ($this->ssl ? 'ssl://' : 'tcp://') . $addr . ':' . $this->port;
        $context = stream_context_create(array_replace_recursive($this->options, ['ssl' => [
            'peer_name' => $this->host,
            'verify_peer' => true,
            'verify_peer_name' => true,
            'allow_self_signed' => false,
            'SNI_enabled' => true,
        ]]));
        $errno = 0;
        $errstr = '';
        $stream = @stream_socket_client($target, $errno, $errstr, Http::TIMEOUT, STREAM_CLIENT_CONNECT, $context);
        if (!\is_resource($stream)) {
            throw new rex_socket_exception('connect failed' . ('' !== $errstr ? ': ' . $errstr : ''));
        }
        stream_set_timeout($stream, $this->timeout);
        $this->stream = $stream;
    }

    protected function writeRequest($method, $path, array $headers = [], $data = '')
    {
        $eol = "\r\n";
        $out = strtoupper($method) . ' ' . $path . ' HTTP/1.1' . $eol;
        foreach ($headers as $key => $value) {
            $out .= str_replace(["\r", "\n"], '', $key . ': ' . $value) . $eol;
        }
        $data = \is_string($data) ? $data : '';
        $out .= 'Content-Length: ' . \strlen($data) . $eol . $eol . $data;
        fwrite($this->stream, $out);

        $raw = '';
        $deadline = microtime(true) + Http::MAX_DURATION;
        while (!feof($this->stream)) {
            $chunk = fread($this->stream, 8192);
            $meta = stream_get_meta_data($this->stream);
            if (!empty($meta['timed_out']) || microtime(true) > $deadline) {
                throw new rex_socket_exception('Timeout!');
            }
            if (false === $chunk) {
                break;
            }
            $raw .= $chunk;
            if (\strlen($raw) > Http::MAX_BYTES + 16384) {
                throw new rex_socket_exception('response too large');
            }
        }
        fclose($this->stream);

        $buffer = fopen('php://temp', 'w+');
        if (false === $buffer) {
            throw new rex_socket_exception('no buffer');
        }
        fwrite($buffer, $raw);
        rewind($buffer);

        return new rex_socket_response($buffer);
    }
}
