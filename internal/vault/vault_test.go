package vault

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateOpenRoundtrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "t.vault")
	v, err := Create(p, "richtig-langes-pw", nil, MFA{TOTPSecret: "ABC"})
	if err != nil {
		t.Fatal(err)
	}
	e := v.UpsertEntry(Entry{Title: "Mail", Password: "geheim1"})
	e.Password = "geheim2"
	v.UpsertEntry(e)
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	if strings.Contains(string(raw), "geheim") || strings.Contains(string(raw), "Mail") {
		t.Fatal("Klartext in der Tresordatei")
	}

	v2, err := Open(p, "richtig-langes-pw", nil)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := v2.Entry(e.ID)
	if !ok || got.Password != "geheim2" || len(got.History) != 1 || got.History[0].Password != "geheim1" {
		t.Fatalf("unerwarteter Eintrag: %+v", got)
	}
	if v2.Data.MFA.TOTPSecret != "ABC" {
		t.Fatal("MFA-Geheimnis fehlt")
	}
	if _, err := Open(p, "falsch", nil); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("falsches Passwort: %v", err)
	}
}

func TestKeyFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "t.vault")
	kf := []byte("schluesseldatei-inhalt")
	if _, err := Create(p, "pw-pw-pw-pw", kf, MFA{}); err != nil {
		t.Fatal(err)
	}
	if need, _ := NeedsKeyFile(p); !need {
		t.Fatal("Schlüsseldatei sollte verlangt werden")
	}
	if _, err := Open(p, "pw-pw-pw-pw", nil); err == nil {
		t.Fatal("Öffnen ohne Schlüsseldatei darf nicht klappen")
	}
	if _, err := Open(p, "pw-pw-pw-pw", []byte("andere")); err == nil {
		t.Fatal("Öffnen mit falscher Schlüsseldatei darf nicht klappen")
	}
	v, err := Open(p, "pw-pw-pw-pw", kf)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.ChangeCredentials("neues-passwort", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(p, "neues-passwort", nil); err != nil {
		t.Fatalf("nach Wechsel: %v", err)
	}
}

func TestTamperDetected(t *testing.T) {
	p := filepath.Join(t.TempDir(), "t.vault")
	if _, err := Create(p, "pw-pw-pw-pw", nil, MFA{}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	// Schlüsseldatei-Flag im Kopf manipulieren: Header ist AAD, also muss das auffallen.
	tampered := strings.Replace(string(raw), `\"keyfile\":false`, `\"keyfile\":true`, 1)
	if tampered == string(raw) {
		t.Fatal("Testaufbau: Flag nicht gefunden")
	}
	raw = []byte(tampered)
	os.WriteFile(p, raw, 0o600)
	if _, err := Open(p, "pw-pw-pw-pw", []byte("x")); err == nil {
		t.Fatal("Manipulation nicht erkannt")
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
