package vault

import (
	"path/filepath"
	"testing"
)

// Zwei Geräte öffnen denselben Tresor (z. B. auf einem NAS) und ändern ihn gleichzeitig.
func TestTwoDevicesMerge(t *testing.T) {
	p := filepath.Join(t.TempDir(), "nas.vault")
	if _, err := Create(p, "a", "pw-pw-pw-pw", nil, MFA{TOTPSecret: "S"}); err != nil {
		t.Fatal(err)
	}
	a, _, _ := Open(p, "a", "pw-pw-pw-pw", nil)
	b, _, _ := Open(p, "a", "pw-pw-pw-pw", nil)

	shared := a.UpsertEntry(Entry{Title: "Gemeinsam", Password: "1"})
	if err := a.Save(); err != nil {
		t.Fatal(err)
	}
	b.UpsertEntry(Entry{Title: "Von B", Password: "2"})
	if err := b.Save(); err != nil { // muss den Eintrag von A übernehmen
		t.Fatal(err)
	}
	if _, ok := b.Entry(shared.ID); !ok {
		t.Fatal("B hat den Eintrag von A überschrieben")
	}

	// A löscht, B hat den Eintrag vorher nicht angefasst -> bleibt gelöscht.
	a.DeleteEntry(shared.ID)
	if err := a.Save(); err != nil {
		t.Fatal(err)
	}
	if changed, err := b.Refresh(); err != nil || !changed {
		t.Fatalf("Refresh: %v %v", changed, err)
	}
	if _, ok := b.Entry(shared.ID); ok {
		t.Fatal("gelöschter Eintrag ist wieder aufgetaucht")
	}
	if len(b.Data.Entries) != 1 || b.Data.Entries[0].Title != "Von B" {
		t.Fatalf("unerwartete Einträge: %+v", b.Data.Entries)
	}

	// Gleicher Eintrag auf beiden Geräten geändert -> neuere Änderung gewinnt.
	e := b.Data.Entries[0]
	a.Refresh()
	ea, _ := a.Entry(e.ID)
	ea.Notes = "alt"
	a.UpsertEntry(ea)
	e.Notes = "neu"
	b.UpsertEntry(e)
	a.Save()
	b.Save()
	c, _, err := Open(p, "a", "pw-pw-pw-pw", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := c.Entry(e.ID); got.Notes != "neu" {
		t.Fatalf("Notiz %q, erwartet neu", got.Notes)
	}
}

func TestPasswordChangedElsewhere(t *testing.T) {
	p := filepath.Join(t.TempDir(), "nas.vault")
	Create(p, "a", "pw-pw-pw-pw", nil, MFA{TOTPSecret: "S"})
	a, _, _ := Open(p, "a", "pw-pw-pw-pw", nil)
	b, _, _ := Open(p, "a", "pw-pw-pw-pw", nil)
	// Passwortwechsel auf Gerät A: Gerät B kann weiter speichern (gleiches Schlüsselpaar),
	// braucht für MFA-Änderungen aber eine neue Anmeldung.
	if err := a.ChangeCredentials("neues-passwort", nil); err != nil {
		t.Fatal(err)
	}
	b.UpsertEntry(Entry{Title: "x"})
	if err := b.Save(); err != nil {
		t.Fatal(err)
	}
	if err := b.SetMFA(MFA{TOTPSecret: "NEU"}); err == nil {
		t.Fatal("MFA-Änderung mit veraltetem Passwort-Schlüssel möglich")
	}
	c, _, err := Open(p, "a", "neues-passwort", nil)
	if err != nil || len(c.Data.Entries) != 1 {
		t.Fatalf("Datei: %v", err)
	}
	if _, _, err := Open(p, "a", "pw-pw-pw-pw", nil); err == nil {
		t.Fatal("altes Passwort funktioniert noch")
	}
}

func TestMoveTo(t *testing.T) {
	dir := t.TempDir()
	v, _ := Create(filepath.Join(dir, "a.vault"), "a", "pw-pw-pw-pw", nil, MFA{})
	v.UpsertEntry(Entry{Title: "x"})
	v.Save()
	if err := v.MoveTo(filepath.Join(dir, "b.vault")); err != nil {
		t.Fatal(err)
	}
	w, _, err := Open(filepath.Join(dir, "b.vault"), "a", "pw-pw-pw-pw", nil)
	if err != nil || len(w.Data.Entries) != 1 {
		t.Fatalf("verschobener Tresor: %v", err)
	}
	if err := w.MoveTo(filepath.Join(dir, "a.vault")); err == nil {
		t.Fatal("Überschreiben einer vorhandenen Datei muss scheitern")
	}
}
