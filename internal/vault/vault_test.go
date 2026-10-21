package vault

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const pw = "richtig-langes-pw"

func newVault(t *testing.T) (string, *Vault) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "t.vault")
	v, err := Create(p, "rene", pw, nil, MFA{TOTPSecret: "TOTPGEHEIMNIS"})
	if err != nil {
		t.Fatal(err)
	}
	return p, v
}

func TestCreateOpenRoundtrip(t *testing.T) {
	p, v := newVault(t)
	e := v.UpsertEntry(Entry{Title: "Mail", Password: "geheim1"})
	e.Password = "geheim2"
	v.UpsertEntry(e)
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	if strings.Contains(string(raw), "geheim") || strings.Contains(string(raw), "Mail") || strings.Contains(string(raw), "TOTPGEHEIMNIS") {
		t.Fatal("Klartext in der Tresordatei")
	}
	v2, mfa, err := Open(p, "René", pw, nil) // Groß-/Kleinschreibung egal? Nein: anderer Name
	if err == nil {
		t.Fatal("unbekannter Benutzer akzeptiert")
	}
	v2, mfa, err = Open(p, "RENE", pw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if v2.User() != "rene" || !v2.IsAdmin() {
		t.Fatalf("Benutzer %q admin=%v", v2.User(), v2.IsAdmin())
	}
	got, ok := v2.Entry(e.ID)
	if !ok || got.Password != "geheim2" || len(got.History) != 1 || got.UpdatedBy != "rene" {
		t.Fatalf("unerwarteter Eintrag: %+v", got)
	}
	if mfa == nil || mfa.TOTPSecret != "TOTPGEHEIMNIS" {
		t.Fatal("MFA fehlt")
	}
	// Mit nur einem Benutzer geht es auch ohne Namen.
	if _, _, err := Open(p, "", pw, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Open(p, "rene", "falsch", nil); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("falsches Passwort: %v", err)
	}
}

func TestKeyFileAndChangeCredentials(t *testing.T) {
	p := filepath.Join(t.TempDir(), "t.vault")
	kf := []byte("schluesseldatei-inhalt")
	if _, err := Create(p, "a", pw, kf, MFA{TOTPSecret: "X"}); err != nil {
		t.Fatal(err)
	}
	if !KeyFileFor(p, "a") {
		t.Fatal("Schlüsseldatei sollte verlangt werden")
	}
	if _, _, err := Open(p, "a", pw, nil); err == nil {
		t.Fatal("Öffnen ohne Schlüsseldatei darf nicht klappen")
	}
	if _, _, err := Open(p, "a", pw, []byte("andere")); err == nil {
		t.Fatal("Öffnen mit falscher Schlüsseldatei darf nicht klappen")
	}
	v, _, err := Open(p, "a", pw, kf)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.ChangeCredentials("neues-passwort", nil); err != nil {
		t.Fatal(err)
	}
	_, mfa, err := Open(p, "a", "neues-passwort", nil)
	if err != nil || mfa.TOTPSecret != "X" {
		t.Fatalf("nach Wechsel: %v %v", err, mfa)
	}
}

func TestTamperDetected(t *testing.T) {
	p, _ := newVault(t)
	raw, _ := os.ReadFile(p)
	var f file
	json.Unmarshal(raw, &f)
	var h header
	json.Unmarshal([]byte(f.Header), &h)
	h.Users[0].MFA = nil // Versuch, die MFA im Kopf zu entfernen
	hb, _ := json.Marshal(h)
	f.Header = string(hb)
	out, _ := json.Marshal(f)
	os.WriteFile(p, out, 0o600)
	if _, _, err := Open(p, "rene", pw, nil); err == nil {
		t.Fatal("Manipulation am Kopf nicht erkannt")
	}
}

func TestMigrateV1(t *testing.T) {
	p := filepath.Join(t.TempDir(), "alt.vault")
	kdf, _ := defaultKDF()
	key, _ := deriveKey(pw, nil, kdf)
	d := Data{Entries: []Entry{{ID: "1", Title: "Alt", Password: "p"}}, LegacyMFA: &MFA{TOTPSecret: "OLD"}}
	pt, _ := json.Marshal(d)
	hv := headerV1{Version: 1, KDF: kdf, Cipher: "aes-256-gcm"}
	hb, _ := json.Marshal(hv)
	box, _ := sealBox(key, pt, string(hb))
	hv.Nonce = box.Nonce
	hb2, _ := json.Marshal(hv)
	box2, _ := func() (Box, error) { // Nonce steht im Kopf, also mit diesem Kopf als AAD neu verschlüsseln
		gcm, _ := newGCM(key)
		return Box{Nonce: hv.Nonce, CT: gcm.Seal(nil, hv.Nonce, pt, hb2)}, nil
	}()
	raw, _ := json.Marshal(fileV1{Header: string(hb2), Ciphertext: box2.CT})
	os.WriteFile(p, raw, 0o600)

	info, _ := ReadLoginInfo(p)
	if !info.Legacy {
		t.Fatal("altes Format nicht erkannt")
	}
	v, mfa, err := Open(p, "", pw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if v.User() != "admin" || mfa == nil || mfa.TOTPSecret != "OLD" || len(v.Data.Entries) != 1 {
		t.Fatalf("Übernahme: user=%q mfa=%v entries=%d", v.User(), mfa, len(v.Data.Entries))
	}
	if !Exists(p + ".v1.bak") {
		t.Fatal("Sicherung des alten Tresors fehlt")
	}
	if info, _ := ReadLoginInfo(p); info.Legacy || len(info.Users) != 1 {
		t.Fatalf("nach Übernahme: %+v", info)
	}
	if _, _, err := Open(p, "admin", pw, nil); err != nil {
		t.Fatal(err)
	}
}

func TestFolders(t *testing.T) {
	v := &Vault{}
	a, _ := v.UpsertFolder(Folder{Name: "A"})
	b, _ := v.UpsertFolder(Folder{Name: "B", ParentID: a.ID})
	a.ParentID = b.ID
	if _, err := v.UpsertFolder(a); err == nil {
		t.Fatal("Zyklus nicht erkannt")
	}
	id := v.FolderByPath([]string{"A", "B", "C"})
	if got := strings.Join(v.FolderPath(id), "/"); got != "A/B/C" {
		t.Fatalf("Pfad %q", got)
	}
	v.UpsertEntry(Entry{Title: "x", FolderID: id})
	v.DeleteFolder(a.ID)
	if len(v.Data.Folders) != 0 || len(v.Data.Entries) != 0 {
		t.Fatalf("nicht alles gelöscht: %+v", v.Data)
	}
}
