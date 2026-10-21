package vault

import (
	"errors"
	"testing"
)

func TestUsers(t *testing.T) {
	p, admin := newVault(t)
	start, err := admin.AddUser("anna", RoleUser)
	if err != nil {
		t.Fatal(err)
	}
	admin.UpsertEntry(Entry{Title: "Gemeinsam", Password: "g"})
	if err := admin.Save(); err != nil {
		t.Fatal(err)
	}
	info, _ := ReadLoginInfo(p)
	if len(info.Users) != 2 {
		t.Fatalf("Benutzer im Kopf: %v", info.Users)
	}
	if _, _, err := Open(p, "", pw, nil); err == nil {
		t.Fatal("ohne Benutzernamen bei zwei Benutzern darf es nicht klappen")
	}

	// Anna meldet sich mit dem Startpasswort an, muss Passwort ändern und MFA einrichten.
	anna, mfa, err := Open(p, "anna", start, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !anna.MustChange() || mfa != nil || anna.IsAdmin() {
		t.Fatalf("mustChange=%v mfa=%v admin=%v", anna.MustChange(), mfa, anna.IsAdmin())
	}
	if len(anna.Data.Entries) != 1 {
		t.Fatal("Anna sieht die gemeinsamen Einträge nicht")
	}
	if err := anna.ChangeCredentials("annas-eigenes-pw", nil); err != nil {
		t.Fatal(err)
	}
	if err := anna.SetMFA(MFA{TOTPSecret: "ANNA"}); err != nil {
		t.Fatal(err)
	}
	if _, err := anna.AddUser("x", RoleUser); err == nil {
		t.Fatal("Nicht-Admin darf Benutzer anlegen")
	}
	_, mfa, err = Open(p, "anna", "annas-eigenes-pw", nil)
	if err != nil || mfa == nil || mfa.TOTPSecret != "ANNA" {
		t.Fatalf("Anna nach Einrichtung: %v %v", err, mfa)
	}
	// Admins MFA ist unverändert.
	if _, m, _ := Open(p, "rene", pw, nil); m.TOTPSecret != "TOTPGEHEIMNIS" {
		t.Fatal("MFA des Admins verändert")
	}

	// Admin entfernt Anna: Tresor wird neu verschlüsselt, Annas laufende Sitzung fliegt raus.
	if err := admin.RemoveUser("rene"); err == nil {
		t.Fatal("Selbst entfernen möglich")
	}
	if err := admin.RemoveUser("anna"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Open(p, "anna", "annas-eigenes-pw", nil); err == nil {
		t.Fatal("entfernte Benutzerin kann noch öffnen")
	}
	anna.UpsertEntry(Entry{Title: "von Anna"})
	if err := anna.Save(); !errors.Is(err, ErrUserRemoved) {
		t.Fatalf("erwartet ErrUserRemoved, bekam %v", err)
	}
	// Der Admin kann weiter öffnen.
	v, _, err := Open(p, "rene", pw, nil)
	if err != nil || len(v.Users()) != 1 {
		t.Fatalf("Admin nach Entfernen: %v", err)
	}
}

func TestLastAdmin(t *testing.T) {
	_, admin := newVault(t)
	if err := admin.SetRole("rene", RoleUser); err == nil {
		t.Fatal("letzter Admin konnte herabgestuft werden")
	}
	admin.AddUser("bob", RoleAdmin)
	if err := admin.SetRole("rene", RoleUser); err != nil {
		t.Fatal(err)
	}
}

func TestResetUserAndSecondDevice(t *testing.T) {
	p, admin := newVault(t)
	start, _ := admin.AddUser("anna", RoleUser)
	anna, _, _ := Open(p, "anna", start, nil)
	anna.ChangeCredentials("annas-eigenes-pw", nil)
	anna.SetMFA(MFA{TOTPSecret: "ANNA"})

	// Zweite Sitzung des Admins (anderer PC) sieht die Änderungen und kann weiter speichern,
	// auch nachdem der Datenschlüssel durch das Zurücksetzen gewechselt hat.
	admin2, _, _ := Open(p, "rene", pw, nil)
	newStart, err := admin.ResetUser("anna")
	if err != nil {
		t.Fatal(err)
	}
	admin2.UpsertEntry(Entry{Title: "vom zweiten PC"})
	if err := admin2.Save(); err != nil {
		t.Fatalf("zweiter PC nach Schlüsselwechsel: %v", err)
	}
	a2, mfa, err := Open(p, "anna", newStart, nil)
	if err != nil || mfa != nil || !a2.MustChange() || len(a2.Data.Entries) != 1 {
		t.Fatalf("nach Zurücksetzen: %v mfa=%v", err, mfa)
	}
	if _, _, err := Open(p, "anna", "annas-eigenes-pw", nil); err == nil {
		t.Fatal("altes Passwort nach Zurücksetzen gültig")
	}
	if err := anna.Save(); err == nil {
		t.Fatal("alte Sitzung nach Zurücksetzen darf nicht speichern")
	}
}
