# PassMind

![PassMind – Portable Password Manager](assets/banner.jpg)

Portabler Passwort-Safe mit Weboberfläche. Eine einzige Programmdatei pro Plattform, keine Installation, keine Cloud. Läuft z. B. direkt vom USB-Stick unter Windows, macOS und Linux.

## So funktioniert es

- Beim Start öffnet PassMind einen kleinen Webserver **nur auf 127.0.0.1** und öffnet die Oberfläche im Standardbrowser.
- Der Tresor ist eine verschlüsselte Datei, standardmäßig `passmind.vault` **direkt neben dem Programm**. Programm und Tresor zusammen auf den Stick kopieren, fertig.
- Der Speicherort ist frei wählbar (im Einrichtungsassistenten, beim Entsperren über „Anderen Tresor öffnen oder neu anlegen“ oder später unter Einstellungen → „Verschieben …“). PassMind merkt sich Tresor, Design und Netzwerk-Anmeldungen in `passmind.json` neben dem Programm.
- Beim Speichern wird die vorherige Fassung als `passmind.vault.bak` behalten.

## Funktionen

- Ordner (beliebig verschachtelt) in einer Baumansicht, Einträge und Ordner per Drag & Drop verschieben (Ordner auf „Alle Einträge“ ziehen = oberste Ebene)
- Einträge mit Titel, Benutzername, Passwort, URL, Notizen und Tags
- Mehrfachauswahl per Auswahlkästchen: mehrere Einträge auf einmal löschen oder verschieben (auch per Ziehen auf einen Ordner)
- Ordner löschen über „Ordner löschen“ oberhalb der Liste (löscht Unterordner und Einträge mit)
- Suche über alle Felder (`Strg+F`), neuer Eintrag mit `Strg+N`, Sperren mit `Strg+L`
- Integrierter **Passwortgenerator**: Zeichen (Länge, Gruppen, ähnliche Zeichen vermeiden) oder Passphrase aus Wörtern
- Stärkeanzeige für Passwörter
- Kopieren in die Zwischenablage mit automatischem Leeren (Standard 20 s)
- Passwort-Verlauf pro Eintrag (die letzten 20)
- Automatische Sperre bei Inaktivität (Standard 5 min)
- **Mehrere Benutzer** pro Tresor, jeder mit eigenem Passwort und eigener Authenticator-App
- **Persönlicher Tresor** (roter Ordner) für jeden Benutzer: eigene Ordner und Einträge, die kein anderer sieht, auch kein Admin
- Helles oder dunkles Design, PassMind merkt sich die Wahl
- **MFA beim Start**: Passwort plus 6-stelliger Code aus einer Authenticator-App (TOTP), dazu 8 Wiederherstellungscodes je Benutzer
- Optional eine **Schlüsseldatei** als zusätzlicher Schlüssel
- CSV-Import (Passwordstate, KeePass 2 „KeePass CSV (1.x)“, KeePassXC, Bitwarden, Excel mit Komma oder Semikolon) und CSV-Export. Nach dem Import zeigt PassMind, welche Spalte in welches Feld ging
- Passwort direkt in der Liste per Auge für 5 Sekunden anzeigen
- **Tresor auf NAS oder Netzlaufwerk**: mehrere Rechner können denselben Tresor nutzen

## Einrichtung

Beim ersten Start führt ein Assistent durch die Einrichtung:

1. **Tresor:** neuen Tresor anlegen oder einen vorhandenen öffnen.
2. **Speicherort und Verbindungsart:** Ordner wählen (lokal, NAS, Netzlaufwerk). Verbindungsart **Standard** nutzt den angemeldeten Benutzer, passend für die lokale Platte oder eine Freigabe, auf die man schon Rechte hat. **Netzwerk-Anmeldung** verbindet eine Freigabe wie `\\nas\daten\passmind` mit eigenem Benutzer und Passwort (nur Windows). Das Passwort wird per Windows-DPAPI verschlüsselt in `passmind.json` gespeichert, nur derselbe Windows-Benutzer auf demselben Rechner kann es lesen; PassMind verbindet die Freigabe beim nächsten Start selbst.
3. **Superuser:** Beim neuen Tresor Benutzername, Master-Passwort, Authenticator-App und Wiederherstellungscodes. Beim vorhandenen Tresor normale Anmeldung.
4. **Design:** hell oder dunkel.
5. **Benutzer:** weitere lokale Benutzer anlegen (jeder immer mit eigener MFA) und auf Wunsch die AD-Anmeldung für den gemischten Betrieb einschalten.

Den Assistenten erreicht man später wieder über „Anderen Tresor öffnen oder neu anlegen“ auf der Anmeldeseite.

## Persönlicher Tresor

Jeder Benutzer hat links einen roten Ordner „Persönlicher Tresor“ mit eigenen Unterordnern. Was dort liegt, kann kein anderer Benutzer lesen, auch kein Admin, denn es ist mit einem eigenen Schlüssel verschlüsselt:

- Lokale Benutzer: Der Schlüssel ist an ihr persönliches Schlüsselpaar gebunden. Eigene Passwortänderungen sind kein Problem. Setzt ein Admin den Benutzer zurück (↺) oder entfernt ihn, ist sein persönlicher Tresor verloren.
- AD-Benutzer: Der Schlüssel ist mit dem AD-Passwort verschlüsselt. Nach einem Passwortwechsel im AD fragt PassMind einmal nach dem bisherigen Passwort. Wer es nicht mehr weiß, kann den persönlichen Tresor leeren und neu beginnen.

Einträge lassen sich per Drag & Drop oder Mehrfachauswahl zwischen gemeinsamem und persönlichem Bereich verschieben. Ordner bleiben in ihrem Bereich. Die Suche findet beides, der Export enthält den eigenen persönlichen Tresor unter „Persönlich/…“.

## Mehrere Benutzer

Wer den Tresor anlegt, ist Admin. Unter Einstellungen → „Benutzer“ legt ein Admin weitere Benutzer an (Rolle „Benutzer“ oder „Admin“) und bekommt dafür ein Startpasswort angezeigt. Das gibt er persönlich weiter. Beim ersten Anmelden legt der neue Benutzer sein eigenes Passwort fest und richtet seine eigene Authenticator-App ein. Danach meldet sich jeder mit Benutzername, eigenem Passwort und eigenem Code an.

- Alle Benutzer sehen und bearbeiten alle gemeinsamen Einträge. Im Eintrag steht, wer ihn zuletzt geändert hat.
- Passwort vergessen oder Handy verloren: Ein Admin klickt beim Benutzer auf ↺ und gibt ein neues Startpasswort heraus. Passwort und Authenticator werden dann neu eingerichtet.
- Ein Admin kann Benutzer entfernen. Der Tresor wird dabei mit einem neuen Schlüssel verschlüsselt, ein alter Zugang öffnet ihn danach nicht mehr. Es bleibt immer mindestens ein Admin.
- Tresore aus älteren PassMind-Versionen werden beim ersten Entsperren umgestellt. Du bist dann Benutzer „admin“. Eine Sicherung der alten Datei bleibt als `.v1.bak` liegen. Wer lieber einen eigenen Namen hat, legt sich selbst als Admin an, meldet sich damit an und entfernt „admin“.

Die Schlüsseldatei ist optional pro Benutzer und wird in den Einstellungen unter „Eigenes Passwort / Schlüsseldatei ändern“ gesetzt.

## Anmeldung mit Active Directory

Liegt der Tresor auf einem Netzlaufwerk in der Domäne, können sich Mitglieder einer AD-Gruppe mit ihrem AD-Konto anmelden. Lokale Benutzer (z. B. der lokale Admin) bleiben bestehen.

1. Als lokaler Admin unter Einstellungen → „Active Directory“ Domänencontroller (z. B. `dc01.firma.local`), Domäne (`firma.local`) und Gruppe (z. B. `GR-PASS-ADM`) eintragen, mit einem Testkonto „Verbindung testen“ und einschalten.
2. PassMind legt neben dem Tresor die Datei `passmind.vault.adkey` an. **Diese Datei per NTFS-Rechten nur für die AD-Gruppe und die Admins lesbar machen.** Mit ihr lässt sich der Tresor öffnen; wer sie nicht lesen kann, kommt auch mit AD-Konto nicht hinein.
3. Ab jetzt reicht es, einen Benutzer in die Gruppe aufzunehmen. Er meldet sich mit `name`, `FIRMA\name` oder `name@firma.local` und seinem AD-Passwort an und richtet beim ersten Mal seine eigene Authenticator-App ein.

Technisch: Anmeldung per LDAPS (Port 636, Zertifikat wird geprüft) mit dem Konto des Benutzers, Prüfung der Gruppe auch über verschachtelte Gruppen. Wird jemand aus der Gruppe genommen, kommt er nicht mehr hinein. Handy verloren: Ein Admin setzt in der Benutzerliste die MFA zurück (↺). Beim Ausschalten wird der Tresor neu verschlüsselt, die alte `.adkey`-Datei ist dann wertlos.

## Tresor auf dem Netzlaufwerk

1. Unter Einstellungen → „Speicherort des Tresors“ → „Verschieben …“ einen Ordner auf dem NAS wählen, z. B. `\\NAS\Freigabe\PassMind` (Windows), `/Volumes/Freigabe` (macOS) oder einen eingehängten Ordner unter Linux. Braucht die Freigabe eine eigene Anmeldung, im Auswahldialog „Netzwerk-Anmeldung“ aufklappen.
2. Auf den anderen Rechnern PassMind starten und im Assistenten „Vorhandenen Tresor öffnen“ wählen.

Ändern zwei Rechner gleichzeitig etwas, führt PassMind die Änderungen beim Speichern zusammen: Pro Eintrag gewinnt die neuere Änderung, Löschungen werden übernommen. Die Uhrzeit der Rechner sollte daher stimmen. Wird ein Benutzer entfernt oder zurückgesetzt, müssen sich die anderen Rechner neu anmelden.

## Starten

1. Passende Datei aus den [Releases](../../releases) laden, z. B. `passmind-windows-amd64.exe`.
2. Auf den USB-Stick kopieren und starten.
3. Beim ersten Start führt ein Assistent durch die [Einrichtung](#einrichtung).

Hinweise zu den Betriebssystemen:

- **Windows:** SmartScreen warnt bei unbekannten Programmen. „Weitere Informationen“ → „Trotzdem ausführen“.
- **macOS:** Die Datei ist nicht signiert. Einmalig `xattr -d com.apple.quarantine passmind-darwin-arm64 && chmod +x passmind-darwin-arm64` im Terminal ausführen, danach per Doppelklick oder `./passmind-darwin-arm64` starten. Intel-Macs nehmen `darwin-amd64`.
- **Linux:** `chmod +x passmind-linux-amd64 && ./passmind-linux-amd64`

Die Windows-Version trägt das PassMind-Icon. Unter macOS und Linux haben einzelne Programmdateien kein eigenes Icon; für Verknüpfungen liegt [`assets/passmind.ico`](assets/passmind.ico) bzw. [`assets/icon.png`](assets/icon.png) bereit.

Das Konsolenfenster muss offen bleiben, solange PassMind läuft. Beenden über den ⏻-Knopf in der Oberfläche oder mit `Strg+C`.

Optionen:

```
-vault <pfad>   anderer Ort für die Tresordatei
-port <nummer>  fester Port statt automatisch
-no-browser     Browser nicht automatisch öffnen (Adresse steht in der Konsole)
-version        Version anzeigen
```

## Sicherheit

| Thema | Umsetzung |
| --- | --- |
| Schlüsselableitung | Argon2id (3 Durchläufe, 64 MiB, 4 Threads), 32 Byte Salt |
| Verschlüsselung | AES-256-GCM mit zufälligem Datenschlüssel; der unverschlüsselte Dateikopf ist als AAD mit authentifiziert |
| Benutzer | Jeder Benutzer hat ein X25519-Schlüsselpaar. Der private Schlüssel ist mit seinem Passwort (Argon2id) verschlüsselt, der Datenschlüssel ist für jeden Benutzer einzeln versiegelt (ECDH + HKDF-SHA256 + AES-256-GCM). Beim Entfernen oder Zurücksetzen eines Benutzers wird der Datenschlüssel erneuert |
| Schlüsseldatei | SHA-256 der Datei, per HMAC mit dem Master-Passwort verknüpft, bevor Argon2id läuft |
| Persönlicher Tresor | Eigener zufälliger Schlüssel je Benutzer; lokal an dessen X25519-Schlüssel versiegelt, bei AD-Benutzern mit Argon2id aus dem AD-Passwort verschlüsselt. Der Inhalt liegt zusätzlich verschlüsselt im gemeinsamen Datenteil |
| Netzwerk-Anmeldung | Windows `WNetAddConnection2` ohne Laufwerksbuchstaben; Passwort per DPAPI (CurrentUser) geschützt |
| MFA | Pro Benutzer, mit dessen Passwort verschlüsselt; TOTP nach RFC 6238 (SHA-1, 6 Stellen, 30 s, ±1 Zeitfenster); Wiederherstellungscodes nur gehasht gespeichert, je einmal gültig |
| Netzwerk | Server lauscht nur auf 127.0.0.1; Host-Header-Prüfung gegen DNS-Rebinding |
| Sitzung | Zufälliger Startlink setzt ein HttpOnly/SameSite=Strict-Cookie; schreibende Anfragen brauchen einen eigenen Header (CSRF-Schutz); strikte Content-Security-Policy |
| Fehlversuche | Ansteigende Wartezeit nach falschen Anmeldungen, einheitliche Fehlermeldung |
| Export | Nur nach erneuter Eingabe des Master-Passworts |

**Wichtig zur MFA:** Bei einer lokalen Tresordatei schützt der TOTP-Code den Zugang über die Oberfläche. Wer die Tresordatei selbst kopiert, muss trotzdem „nur“ das Passwort eines Benutzers (und ggf. dessen Schlüsseldatei) knacken. Jeder Benutzer sollte deshalb ein starkes Passwort haben. Für echten zweiten Faktor bei der Verschlüsselung die **Schlüsseldatei** nutzen und getrennt vom Tresor aufbewahren.

Vergisst ein Benutzer sein Passwort, kann ein Admin ihn zurücksetzen. Kennt kein Admin mehr sein Passwort (bzw. hat seine Schlüsseldatei), gibt es **keine Möglichkeit**, den Tresor wiederherzustellen. Regelmäßig eine Kopie von `passmind.vault` sichern.

## Selbst bauen

Benötigt Go (Version siehe `go.mod`).

```
go test ./...
./build.sh          # alle Plattformen nach ./dist
go build .          # nur für das aktuelle System
```

Das Windows-Icon und die Versionsinfos stecken in `rsrc_windows_*.syso`. Nach Änderungen an `winres/` neu erzeugen mit:

```
go run github.com/tc-hib/go-winres@latest make --arch amd64,arm64
```

Ein Git-Tag `v*` baut über GitHub Actions automatisch ein Release mit allen Plattformen.

## Lizenz

PassMind ist freie Software: Copyright © 2026 afamaus.

Du kannst das Programm unter den Bedingungen der **GNU General Public License Version 3** (oder, nach deiner Wahl, jeder späteren Version), wie von der Free Software Foundation veröffentlicht, weitergeben und verändern. Wer eine veränderte Fassung weitergibt, muss sie ebenfalls unter der GPL samt Quelltext weitergeben. PassMind wird ohne jede Gewährleistung bereitgestellt. Der vollständige Text steht in [LICENSE](LICENSE).

**Name und Logo** ("PassMind", Banner, Logo und Icons) sind von der GPL ausgenommen und bleiben bei afamaus. Abgewandelte Fassungen (Forks) bitte unter eigenem Namen und Logo veröffentlichen.

Fremdkomponenten und ihre Lizenzen stehen in [NOTICE](NOTICE). Sicherheitslücken bitte vertraulich melden, siehe [SECURITY.md](SECURITY.md).

## Mitmachen

Fehlermeldungen und Vorschläge gern als [Issue](https://github.com/afamaus/passmind/issues), Änderungen als Pull Request. Mit einem Pull Request stellst du deinen Beitrag unter dieselbe Lizenz (GPLv3 oder später).
