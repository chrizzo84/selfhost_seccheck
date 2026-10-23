# SelfHost SecCheck

[English](README.md) · **Deutsch**

Security-Checks für Self-Hosted-Software. Du gibst die URL deiner Instanz ein, wählst die Anwendung (oder
lässt sie erkennen) und bekommst eine Note von **A+ bis F**. Der Scanner prüft TLS-Konfiguration, Zertifikat,
Security-Header, exponierte Dateien, Versionen, bekannte Sicherheitslücken und anwendungsspezifische
Schwachstellen, etwa ein Nextcloud-Datenverzeichnis im Webroot oder einen nie abgeschlossenen
Einrichtungsassistenten.

Alle Checks sind **rein lesend** (GET/TRACE-Anfragen, TLS-Handshakes, DNS-Abfragen) und laufen **ohne
Anmeldung**. Scanne nur Instanzen, die du betreibst oder ausdrücklich testen darfst.

## Funktionen

- **Bericht** mit Empfehlungen, Export als JSON und Markdown
- **Konfig-Schnipsel** für nginx, Apache, Caddy und Traefik, passend zu den Befunden
- **App-Erkennung** anhand der URL
- **Dashboard** aller gescannten Instanzen mit Note und Trend
- **Verlauf** pro Instanz mit Score-Diagramm und Vergleich zum letzten Scan (neu / behoben)
- **Geplante Scans** (alle 6 Stunden, täglich, wöchentlich) mit **Benachrichtigung** über ntfy, Gotify, Pushover
  oder E-Mail, wenn neue Probleme auftauchen oder sich die Note verschlechtert
- **Akzeptierte Risiken**: Befunde pro Instanz akzeptieren; sie bleiben sichtbar, zählen aber nicht mehr in die Note
- **Bekannte Sicherheitslücken** der erkannten Version aus den GitHub Security Advisories
- **Vollständige Cipher-Analyse** mit sslyze (SSLv2/v3, RC4, 3DES, …)
- Oberfläche und Berichte auf **Deutsch und Englisch**

Die Liste der unterstützten Anwendungen und aller Checks steht in der [englischen README](README.md#supported-applications).

## Schnellstart

### Docker (empfohlen)

```bash
git clone https://github.com/chrizzo84/selfhost-seccheck.git
cd selfhost-seccheck
docker compose up -d --build        # http://127.0.0.1:8000, Daten in ./data
```

Die Compose-Datei bindet nur an `127.0.0.1`. Lies vor dem Freigeben [Sicher betreiben](#sicher-betreiben).
Für eine deutsche Oberfläche reicht ein deutscher Browser; Standard für CLI und geplante Scans setzt
`SECCHECK_LANG=de`.

### Ohne Docker

Benötigt Python 3.12 oder neuer.

```bash
./start.sh                  # legt .venv an, installiert Abhängigkeiten, läuft im Hintergrund
./stop.sh
```

Ist Port 8000 belegt, weicht `start.sh` auf den nächsten freien Port aus und gibt die URL aus. Optionen:
`PORT=9000 ./start.sh` (fester Port), `HOST=0.0.0.0 ./start.sh` (im Netzwerk erreichbar), `./start.sh -f`
(im Vordergrund). Das Log liegt in `.run/seccheck.log`.

### Kommandozeile

Für Cron oder CI; der Exit-Code ist 1 bei Note D/F, Scans landen hier nicht im Verlauf.

```bash
seccheck --lang de scan nextcloud https://cloud.example.com
seccheck --lang de list
```

## Bewertung

Ein Fehlschlag zieht je nach Schwere Punkte ab (kritisch 40, hoch 20, mittel 8, niedrig 3), eine Warnung die
Hälfte. Noten: A+ ≥ 97, A ≥ 90, B ≥ 80, C ≥ 65, D ≥ 50, sonst F. Ein kritischer Fehlschlag ergibt immer F, ein
hoher höchstens C. Akzeptierte Risiken zählen nicht.

## Konfiguration

Alle Umgebungsvariablen stehen in der [englischen README](README.md#configuration). Die wichtigsten:
`SECCHECK_LANG` (Standardsprache), `SECCHECK_DATA_DIR` (SQLite-Daten), `SECCHECK_BLOCK_PRIVATE=1` (private
Netze als Ziel sperren) und `GITHUB_TOKEN` (höheres Rate-Limit für Versions- und Advisory-Abfragen).
Benachrichtigungen konfigurierst du in der Oberfläche unter **Einstellungen**.

## Sicher betreiben

- **Die Oberfläche hat keine eigene Anmeldung.** Betreibe sie lokal oder hinter einem Reverse-Proxy mit
  Authentifizierung.
- **Nicht als öffentlichen Scanner anbieten** ohne `SECCHECK_BLOCK_PRIVATE=1`, sonst lässt sich damit dein
  internes Netz abtasten. Rate-Limiting und ein Nachweis der Domain-Inhaberschaft fehlen auch dann.
- fail2ban-Regeln gegen `.env`/`.git`-Abfragen können den Scanner sperren. Der Scanner meldet sich mit dem
  User-Agent `SelfHostSecCheck/<version>`.

## Mitmachen

Beiträge sind willkommen. Die Anleitung steht in [CONTRIBUTING.md](CONTRIBUTING.md) (Englisch);
Sicherheitsprobleme in SecCheck selbst meldest du wie in [SECURITY.md](SECURITY.md) beschrieben.

## Lizenz

[GNU Affero General Public License v3.0 oder später](LICENSE).
