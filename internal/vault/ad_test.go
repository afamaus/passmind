package vault

import (
	"errors"
	"os"
	"testing"
)

func TestADGroupAccess(t *testing.T) {
	p, admin := newVault(t)
	if _, _, err := OpenAD(p, "anna", "ad-passwort"); err == nil {
		t.Fatal("AD-Anmeldung ohne Einrichtung möglich")
	}
	if err := admin.EnableAD(ADConfig{Server: "dc01", Domain: "firma.local", Group: "GR-PASS-ADM"}); err != nil {
		t.Fatal(err)
	}
	if info, _ := ReadLoginInfo(p); info.ADDomain != "firma.local" || len(info.Users) != 2 {
		t.Fatalf("LoginInfo: %+v", info)
	}
	if !Exists(ADKeyPath(p)) {
		t.Fatal("Schlüsseldatei fehlt")
	}

	// Erste Anmeldung: noch keine MFA.
	anna, mfa, err := OpenAD(p, "anna", "ad-passwort")
	if err != nil {
		t.Fatal(err)
	}
	if mfa != nil || !anna.IsADUser() || anna.IsAdmin() || anna.User() != "anna" {
		t.Fatalf("Anna: mfa=%v ad=%v admin=%v", mfa, anna.IsADUser(), anna.IsAdmin())
	}
	if err := anna.SetMFA(MFA{TOTPSecret: "ANNA"}); err != nil {
		t.Fatal(err)
	}
	if err := anna.ChangeCredentials("x", nil); err == nil {
		t.Fatal("AD-Benutzer kann Passwort ändern")
	}
	anna.UpsertEntry(Entry{Title: "von Anna"})
	if err := anna.Save(); err != nil {
		t.Fatal(err)
	}
	_, mfa, err = OpenAD(p, "ANNA", "ad-passwort")
	if err != nil || mfa == nil || mfa.TOTPSecret != "ANNA" {
		t.Fatalf("zweite Anmeldung: %v %v", mfa, err)
	}

	// Admin sieht Anna und Annas Eintrag; MFA zurücksetzen.
	if err := admin.Save(); err != nil {
		t.Fatal(err)
	}
	if len(admin.Data.Entries) != 1 {
		t.Fatalf("Einträge beim Admin: %d", len(admin.Data.Entries))
	}
	var seen bool
	for _, u := range admin.Users() {
		if u.Name == "anna" && u.AD && u.MFA {
			seen = true
		}
		if u.Name == groupSlotName {
			t.Fatal("Gruppen-Slot in der Benutzerliste")
		}
	}
	if !seen {
		t.Fatalf("Anna fehlt: %+v", admin.Users())
	}
	if _, err := admin.ResetUser("anna"); err != nil {
		t.Fatal(err)
	}
	if _, mfa, _ := OpenAD(p, "anna", "ad-passwort"); mfa != nil {
		t.Fatal("MFA nicht zurückgesetzt")
	}
	if _, err := admin.AddUser("Anna", RoleUser); err == nil {
		t.Fatal("lokaler Benutzer mit AD-Namen angelegt")
	}

	// Ohne Schlüsseldatei kein Zugang.
	key, _ := os.ReadFile(ADKeyPath(p))
	os.Remove(ADKeyPath(p))
	if _, _, err := OpenAD(p, "anna", "ad-passwort"); !errors.Is(err, ErrADKey) {
		t.Fatalf("ohne Schlüsseldatei: %v", err)
	}
	os.WriteFile(ADKeyPath(p), key, 0o600)

	// Ausschalten: alte Schlüsseldatei öffnet nichts mehr, offene AD-Sitzung wird beendet.
	ad2, _, err := OpenAD(p, "anna", "ad-passwort")
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.DisableAD(); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(ADKeyPath(p), key, 0o600)
	if _, _, err := OpenAD(p, "anna", "ad-passwort"); err == nil {
		t.Fatal("nach dem Ausschalten noch Zugang")
	}
	ad2.UpsertEntry(Entry{Title: "y"})
	if err := ad2.Save(); !errors.Is(err, ErrUserRemoved) {
		t.Fatalf("AD-Sitzung nach dem Ausschalten: %v", err)
	}
	if _, _, err := Open(p, "rene", pw, nil); err != nil {
		t.Fatalf("lokaler Admin: %v", err)
	}
}
