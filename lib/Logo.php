<?php

declare(strict_types=1);

namespace Klxm\Hub;

use Klxm\Hub\Oidc\Client;
use rex_path;

/**
 * Logo des Anbieters für den Anmelde-Link: Discovery-Feld `logo_uri` (nicht im OIDC-Standard, optional, nur https),
 * einmal geladen, als SVG streng bereinigt (nur Formen, keine Skripte, Stile, Verweise, Ereignisse oder Texte) und in
 * redaxo/data/addons/klxm_hub/ abgelegt – die Anmeldeseite lädt nie etwas vom Anbieter nach. Ohne Logo: null.
 *
 * Bereinigt wird nicht durch Entfernen, sondern durch Neuaufbau: aus dem gelesenen Dokument werden nur erlaubte Elemente
 * (Namensraum SVG) mit erlaubten Attributen und harmlosen Werten in ein neues Dokument übernommen. Namensraum-
 * Deklarationen, CDATA, Kommentare, Entitäten und Texte gelangen so nie in die Ausgabe.
 */
final class Logo
{
    private const int MAX = 65536;
    private const string NS = 'http://www.w3.org/2000/svg';
    private const array TAGS = ['svg', 'g', 'path', 'circle', 'ellipse', 'rect', 'line', 'polyline', 'polygon'];
    /** erlaubte Attribute (klein) → Schreibweise in der Ausgabe */
    private const array ATTRS = ['viewbox' => 'viewBox', 'd' => 'd', 'cx' => 'cx', 'cy' => 'cy', 'r' => 'r', 'rx' => 'rx', 'ry' => 'ry',
        'x' => 'x', 'y' => 'y', 'x1' => 'x1', 'y1' => 'y1', 'x2' => 'x2', 'y2' => 'y2', 'width' => 'width', 'height' => 'height',
        'points' => 'points', 'fill' => 'fill', 'stroke' => 'stroke', 'stroke-width' => 'stroke-width', 'stroke-linecap' => 'stroke-linecap',
        'stroke-linejoin' => 'stroke-linejoin', 'opacity' => 'opacity', 'fill-opacity' => 'fill-opacity', 'stroke-opacity' => 'stroke-opacity',
        'fill-rule' => 'fill-rule', 'transform' => 'transform'];

    /**
     * Inline-SVG (dekorativ) oder null – liest nur die lokale Kopie (nie ein Abruf beim Anzeigen der Anmeldeseite) und
     * bereinigt sie bei jeder Ausgabe erneut (auch Kopien älterer Fassungen gehen so durch die aktuelle Bereinigung).
     */
    public static function svg(): ?string
    {
        $file = self::file((string) (Settings::oidc()['issuer'] ?? ''));
        if (null === $file || !is_file($file)) {
            return null;
        }
        $svg = (string) file_get_contents($file);

        return '' !== $svg ? self::clean($svg) : null;
    }

    /** Logo neu laden und ablegen (beim Speichern der Einstellungen bzw. Prüfen der Discovery); true = Logo vorhanden */
    public static function refresh(string $issuer): bool
    {
        $file = self::file($issuer);
        if (null === $file) {
            return false;
        }
        $svg = self::load($issuer) ?? '';
        @mkdir(\dirname($file), 0o775, true);
        @file_put_contents($file, $svg, LOCK_EX);

        return '' !== $svg;
    }

    private static function file(string $issuer): ?string
    {
        return '' === $issuer ? null : rex_path::addonData(HubAddon::NAME, 'logo-' . substr(hash('sha256', $issuer), 0, 16) . '.svg');
    }

    private static function load(string $issuer): ?string
    {
        try {
            $uri = (string) (Client::discovery($issuer)['logo_uri'] ?? '');
            // nur https (http nur mit KLXM_HUB_ALLOW_HTTP=1 wie bei den Endpunkten)
            if (!preg_match(Http::allowHttp() ? '~^https?://[^\s]+$~' : '~^https://[^\s]+$~', $uri)) {
                return null;
            }
            $r = Http::request('GET', $uri, ['Accept' => 'image/svg+xml']);
        } catch (\Throwable) {
            return null;   // Anbieter nicht erreichbar: Link ohne Logo, die Anmeldung selbst ist davon nicht betroffen
        }
        if (200 !== $r['status'] || \strlen($r['body']) > self::MAX) {
            return null;
        }

        return self::clean($r['body']);
    }

    /** Nur erlaubte Elemente und Attribute mit harmlosen Werten, neu aufgebaut (siehe Klassenbeschreibung). */
    public static function clean(string $svg): ?string
    {
        // nur UTF-8 ohne NUL und ohne DTD – auch keine über eine andere Kodierung (UTF-7, UTF-16 …) versteckte
        if (\strlen($svg) > self::MAX || !str_contains($svg, '<svg') || str_contains($svg, "\0") || !mb_check_encoding($svg, 'UTF-8')
            || preg_match('~<!DOCTYPE|<!ENTITY~i', $svg)
            || (preg_match('~^\s*<\?xml\b[^>]*\bencoding\s*=\s*["\']([^"\']*)~i', $svg, $m) && 'utf-8' !== strtolower($m[1]))) {
            return null;
        }
        $doc = new \DOMDocument();
        if (!@$doc->loadXML($svg, LIBXML_NONET) || null !== $doc->doctype) {
            return null;
        }
        $root = $doc->documentElement;
        if (!$root || !self::allowedElement($root) || 'svg' !== strtolower($root->localName)) {
            return null;
        }
        $out = new \DOMDocument('1.0', 'UTF-8');
        $copy = static function (\DOMElement $from, \DOMNode $parent, int $depth) use (&$copy, $out): void {
            $el = $out->createElementNS(self::NS, strtolower($from->localName));
            foreach ($from->attributes as $a) {
                $n = strtolower($a->localName);
                $v = trim((string) $a->value);
                // Attribute ohne Namensraum, nur aus der Liste; Werte nur aus Zahlen, Buchstaben und Zeichen für Pfade,
                // Farben und Transformationen – kein url(…), var(…), keine CSS-Escapes (\), keine Skript-Adressen
                if (null === $a->namespaceURI && isset(self::ATTRS[$n]) && \strlen($v) <= 20000
                    && preg_match('~^[\w\s#.,%()+-]*$~', $v) && !preg_match('~url|var\(|expression|script~i', $v)) {
                    $el->setAttribute(self::ATTRS[$n], $v);
                }
            }
            $parent->appendChild($el);
            if ($depth >= 32) {
                return;
            }
            foreach ($from->childNodes as $c) {
                // Texte (auch CDATA), Kommentare, Anweisungen und Entitäten bleiben weg; title/desc ebenso (dekorativ)
                if ($c instanceof \DOMElement && self::allowedElement($c) && 'svg' !== strtolower($c->localName)) {
                    $copy($c, $el, $depth + 1);
                }
            }
        };
        $copy($root, $out, 0);
        $svgEl = $out->documentElement;
        if (!$svgEl instanceof \DOMElement) {
            return null;
        }
        $svgEl->setAttribute('class', 'klxm-hub-login-logo');
        $svgEl->setAttribute('aria-hidden', 'true');
        $svgEl->setAttribute('focusable', 'false');
        $res = $out->saveXML($svgEl);

        return false !== $res && \strlen($res) <= self::MAX ? $res : null;
    }

    /** Element aus der Liste im Namensraum SVG, ohne Präfix (ohne Namensraum nur bei Dateien ganz ohne xmlns) */
    private static function allowedElement(\DOMElement $el): bool
    {
        return \in_array(strtolower($el->localName), self::TAGS, true) && \in_array($el->namespaceURI, [self::NS, null], true)
            && '' === (string) $el->prefix;
    }
}
