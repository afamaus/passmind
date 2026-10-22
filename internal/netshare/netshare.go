// Package netshare verbindet Netzwerkfreigaben mit eigenen Zugangsdaten (Windows) und schützt
// das gespeicherte Passwort mit den Mitteln des Betriebssystems.
package netshare

import (
	"errors"
	"strings"
)

// Arten, wie der Tresor-Ort erreicht wird.
const (
	ModeDefault = "default" // mit dem angemeldeten Benutzer (lokale Platte, bereits berechtigte Freigabe)
	ModeNetwork = "network" // Freigabe mit eigenem Benutzer und Passwort verbinden
)

// ErrUnsupported bedeutet, dass das Betriebssystem keine Netzwerk-Anmeldung durch PassMind kennt.
var ErrUnsupported = errors.New("Die Netzwerk-Anmeldung gibt es nur unter Windows. Bitte die Freigabe im Betriebssystem verbinden (macOS: Finder → Gehe zu → Mit Server verbinden, Linux: Dateimanager) und dann den Ordner wählen.")

// ShareRoot liefert aus einem UNC-Pfad wie \\nas\daten\passmind\x.vault die Freigabe \\nas\daten.
func ShareRoot(path string) (string, bool) {
	p := strings.ReplaceAll(strings.TrimSpace(path), "/", `\`)
	if !strings.HasPrefix(p, `\\`) {
		return "", false
	}
	parts := strings.Split(strings.TrimPrefix(p, `\\`), `\`)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" || parts[0] == "?" || parts[0] == "." {
		return "", false
	}
	return `\\` + parts[0] + `\` + parts[1], true
}
