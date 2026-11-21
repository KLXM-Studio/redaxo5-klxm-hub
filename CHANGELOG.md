# Changelog

## 0.1.0 – 2026-11-21

Erste Fassung für REDAXO 5 (ab 5.17, PHP ab 8.3), gleicher Funktionsumfang wie die Fassung für REDAXO 6 in
Version 0.1.3 (einschließlich ihrer Sicherheitshärtungen).

- Anmeldung im Backend über den Agentur Hub (OpenID Connect): PKCE S256, state an die Backend-Sitzung gebunden,
  nonce, RFC 9207 `iss`, ID-Token RS256 über JWKS mit Schlüsselwechsel, `at_hash`, zweiter Faktor über `amr`.
  Einstieg vom Hub (`step=start&iss=…&login_hint=…`) und dezenter Link mit Logo des Anbieters auf der Anmeldeseite.
- Agentur-Konten: Zuordnung über Issuer + `sub`, Anlage bei der ersten Anmeldung (abschaltbar), ohne Passwort,
  gekennzeichnet; Rollen aus dem Claim `roles` (`admin`, `redaktion` → einstellbare Rolle), Abgleich bei jeder
  Anmeldung; vorhandene Benutzer werden nie übernommen; lokal sperrbar (Sitzungen enden sofort); Sitzungen eines
  Agentur-Kontos per Passkey werden beendet (Anmeldung nur über den Hub).
- Signierte Status-Abfrage `status-v1` (`rex-api-call=klxm_hub_status`, `system: "redaxo5"`): Ed25519, ±300 s, Nonce
  erst nach gültiger Signatur (660 s gemerkt); Versionen, AddOns und PlugIns, Ampel, letzte Sicherung, Fehlerprotokoll
  (Feld `log`), Kategorien der Meldungen (`technical`, `setup`, `editorial`).
- Selbstauskunft `klxm-instance-v1` unter `/.well-known/klxm-studio` bzw. `rex-api-call=klxm_hub_instance`.
- Abrufe über `rex_socket` mit fester, geprüfter Zieladresse (kein SSRF ins interne Netz, kein DNS-Rebinding), Größen-
  und Zeitlimit; Ausnahmen nur per Umgebungsvariable (`KLXM_HUB_ALLOW_PRIVATE_NETWORK`, `KLXM_HUB_ALLOW_HTTP`).
- Logo des Anbieters (`logo_uri`) als neu aufgebautes, streng bereinigtes SVG, lokal abgelegt; Befehl `klxm_hub:logo`.
- Einstellungen (AddOns → Agentur Hub): Client-Geheimnis verschlüsselt bzw. aus `KLXM_HUB_CLIENT_SECRET`, Adressen
  für den Hub, Vorschau der Status-Antwort; Seite „Agentur-Konten“.
- Rate-Limit je IP, Protokoll im Systemprotokoll, Erweiterungspunkte `KLXM_HUB_STATUS` und `KLXM_HUB_USER_MAPPING`,
  Selbsttest `klxm_hub:selftest`. Alles standardmäßig aus.
