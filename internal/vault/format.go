package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

const formatVersion = 2

// Slot ist der Zugang eines Benutzers im unverschlüsselten Dateikopf. Jeder Benutzer hat ein
// eigenes X25519-Schlüsselpaar; der private Schlüssel und die MFA-Daten sind mit dem aus seinem
// Passwort abgeleiteten Schlüssel verschlüsselt, der Datenschlüssel ist an seinen öffentlichen
// Schlüssel versiegelt. Der ganze Kopf ist AAD der Daten, Manipulationen fallen also auf.
type Slot struct {
	User       string    `json:"user"`
	KDF        KDFParams `json:"kdf"`
	KeyFile    bool      `json:"keyfile"`
	Pub        []byte    `json:"pub"`
	Priv       Box       `json:"priv"`
	DEK        SealedKey `json:"dek"`
	MFA        *Box      `json:"mfa,omitempty"`
	MustChange bool      `json:"mustChange,omitempty"`
	ChangedAt  time.Time `json:"changedAt"`
}

type header struct {
	Version int    `json:"version"`
	Cipher  string `json:"cipher"`
	Users   []Slot `json:"users"`
}

type file struct {
	Header string `json:"header"` // exakt die Bytes, die als AAD dienen
	Data   Box    `json:"data"`
}

func aadPriv(u string) string { return "pm-priv:" + strings.ToLower(u) }
func aadDEK(u string) string  { return "pm-dek:" + strings.ToLower(u) }
func aadMFA(u string) string  { return "pm-mfa:" + strings.ToLower(u) }

// parse liest Kopf und Datenteil. Für Format 1 wird version=1 und kein Fehler geliefert.
func parse(raw []byte) (version int, h header, f file, err error) {
	var probe struct {
		Header string `json:"header"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return 0, h, f, fmt.Errorf("Tresordatei ist beschädigt: %w", err)
	}
	var v struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal([]byte(probe.Header), &v); err != nil {
		return 0, h, f, fmt.Errorf("Tresorkopf ist beschädigt: %w", err)
	}
	switch v.Version {
	case 1:
		return 1, h, f, nil
	case formatVersion:
	default:
		return 0, h, f, fmt.Errorf("Tresorversion %d wird nicht unterstützt. Bitte PassMind aktualisieren.", v.Version)
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return 0, h, f, fmt.Errorf("Tresordatei ist beschädigt: %w", err)
	}
	if err := json.Unmarshal([]byte(f.Header), &h); err != nil {
		return 0, h, f, fmt.Errorf("Tresorkopf ist beschädigt: %w", err)
	}
	if h.Cipher != "aes-256-gcm" {
		return 0, h, f, fmt.Errorf("unbekanntes Verschlüsselungsverfahren %q", h.Cipher)
	}
	return formatVersion, h, f, nil
}

func findSlot(slots []Slot, user string) int {
	for i, s := range slots {
		if strings.EqualFold(s.User, user) {
			return i
		}
	}
	return -1
}

// LoginInfo beschreibt, was die Anmeldeseite über einen Tresor wissen muss.
type LoginInfo struct {
	Users         []string `json:"users"`
	KeyFileUsers  []string `json:"keyFileUsers"`  // Benutzer, die eine Schlüsseldatei brauchen
	KeyFileNeeded bool     `json:"keyFileNeeded"` // Format 1: ob eine Schlüsseldatei verlangt wird
	Legacy        bool     `json:"legacy"`
}

// ReadLoginInfo liest die Benutzernamen aus dem Kopf (ohne zu entschlüsseln).
func ReadLoginInfo(path string) (LoginInfo, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return LoginInfo{}, err
	}
	ver, h, _, err := parse(raw)
	if err != nil {
		return LoginInfo{}, err
	}
	if ver == 1 {
		var ff fileV1
		var hv headerV1
		json.Unmarshal(raw, &ff)
		json.Unmarshal([]byte(ff.Header), &hv)
		return LoginInfo{Users: []string{}, KeyFileUsers: []string{}, KeyFileNeeded: hv.KeyFileNeeded, Legacy: true}, nil
	}
	info := LoginInfo{Users: []string{}, KeyFileUsers: []string{}}
	for _, s := range h.Users {
		info.Users = append(info.Users, s.User)
		if s.KeyFile {
			info.KeyFileUsers = append(info.KeyFileUsers, s.User)
		}
	}
	return info, nil
}

// KeyFileFor meldet, ob der Benutzer eine Schlüsseldatei braucht.
func KeyFileFor(path, user string) bool {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	ver, h, _, err := parse(raw)
	if err != nil || ver != formatVersion {
		info, _ := ReadLoginInfo(path)
		return info.KeyFileNeeded
	}
	if i := slotFor(h.Users, user); i >= 0 {
		return h.Users[i].KeyFile
	}
	return false
}

// slotFor sucht den Slot zum Benutzernamen; ohne Namen und mit nur einem Benutzer wird dieser genommen.
func slotFor(slots []Slot, user string) int {
	if user == "" && len(slots) == 1 {
		return 0
	}
	return findSlot(slots, user)
}

var errNoUser = errors.New("unbekannter Benutzer")
