package vault

import (
	"errors"
	"testing"
)

func titles(d *Data) map[string]bool {
	m := map[string]bool{}
	if d != nil {
		for _, e := range d.Entries {
			m[e.Title] = true
		}
	}
	return m
}

func TestPersonalLocal(t *testing.T) {
	p, admin := newVault(t)
	start, err := admin.AddUser("anna", RoleUser)
	if err != nil {
		t.Fatal(err)
	}
	anna, _, err := Open(p, "anna", start, nil)
	if err != nil {
		t.Fatal(err)
	}
	f, err := anna.SaveFolder(Folder{Name: "Bank"}, true)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := anna.SaveEntry(Entry{Title: "Annas Konto", Password: "p1", FolderID: f.ID}, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := anna.SaveEntry(Entry{Title: "falscher Ordner", FolderID: f.ID}, false); err == nil {
		t.Fatal("gemeinsamer Eintrag in persönlichem Ordner möglich")
	}
	if err := anna.Save(); err != nil {
		t.Fatal(err)
	}
	// Anna ändert ihr Passwort: der persönliche Tresor bleibt lesbar.
	if err := anna.ChangeCredentials("annas-neues-pw", nil); err != nil {
		t.Fatal(err)
	}

	// Der Admin sieht den Eintrag nicht, auch nicht nach dem Zusammenführen.
	if _, err := admin.Refresh(); err != nil {
		t.Fatal(err)
	}
	if titles(&admin.Data)["Annas Konto"] || titles(admin.PersonalData())["Annas Konto"] {
		t.Fatal("Admin sieht Annas persönlichen Eintrag")
	}
	if _, ok := admin.Entry(secret.ID); ok {
		t.Fatal("Admin findet Annas Eintrag per ID")
	}
	admin.UpsertEntry(Entry{Title: "vom Admin"})
	if err := admin.Save(); err != nil {
		t.Fatal(err)
	}

	anna2, _, err := Open(p, "anna", "annas-neues-pw", nil)
	if err != nil {
		t.Fatal(err)
	}
	got, personal, ok := anna2.Lookup(secret.ID)
	if !ok || !personal || got.Password != "p1" || got.FolderID != f.ID {
		t.Fatalf("Annas Eintrag nach erneutem Öffnen: %+v personal=%v ok=%v", got, personal, ok)
	}

	// Zwei Geräte von Anna ändern gleichzeitig: beide Einträge bleiben.
	anna.SaveEntry(Entry{Title: "Gerät 1"}, true)
	anna2.SaveEntry(Entry{Title: "Gerät 2"}, true)
	if err := anna.Save(); err != nil {
		t.Fatal(err)
	}
	if err := anna2.Save(); err != nil {
		t.Fatal(err)
	}
	anna3, _, _ := Open(p, "anna", "annas-neues-pw", nil)
	if tt := titles(anna3.PersonalData()); !tt["Gerät 1"] || !tt["Gerät 2"] || !tt["Annas Konto"] {
		t.Fatalf("persönliche Einträge nach Zusammenführen: %v", tt)
	}

	// Verschieben zwischen den Bereichen.
	shared, _, _ := anna3.Lookup(secret.ID)
	moved, err := anna3.SaveEntry(Entry{ID: shared.ID, Title: shared.Title, Password: "p2"}, false)
	if err != nil || moved.ID != secret.ID || len(moved.History) != 1 {
		t.Fatalf("verschieben: %+v %v", moved, err)
	}
	if err := anna3.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Refresh(); err != nil {
		t.Fatal(err)
	}
	if !titles(&admin.Data)["Annas Konto"] {
		t.Fatal("in den gemeinsamen Bereich verschobener Eintrag fehlt beim Admin")
	}

	// Admin setzt Anna zurück: ihr persönlicher Tresor ist weg, sie startet leer.
	start, err = admin.ResetUser("anna")
	if err != nil {
		t.Fatal(err)
	}
	anna4, _, err := Open(p, "anna", start, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(anna4.PersonalData().Entries); n != 0 {
		t.Fatalf("nach Zurücksetzen noch %d persönliche Einträge", n)
	}
}

func TestPersonalAD(t *testing.T) {
	p, admin := newVault(t)
	if err := admin.EnableAD(ADConfig{Server: "dc01", Domain: "firma.local", Group: "GR"}); err != nil {
		t.Fatal(err)
	}
	anna, _, err := OpenAD(p, "anna", "altes-pw")
	if err != nil {
		t.Fatal(err)
	}
	if err := anna.SetMFA(MFA{TOTPSecret: "A"}); err != nil {
		t.Fatal(err)
	}
	if _, err := anna.SaveEntry(Entry{Title: "privat"}, true); err != nil {
		t.Fatal(err)
	}
	if err := anna.Save(); err != nil {
		t.Fatal(err)
	}

	// Ben ist in derselben Gruppe, sieht Annas persönlichen Tresor aber nicht.
	ben, _, err := OpenAD(p, "ben", "bens-pw")
	if err != nil {
		t.Fatal(err)
	}
	if titles(ben.PersonalData())["privat"] || titles(&ben.Data)["privat"] {
		t.Fatal("Ben sieht Annas persönlichen Eintrag")
	}

	again, _, _ := OpenAD(p, "anna", "altes-pw")
	if !titles(again.PersonalData())["privat"] {
		t.Fatal("persönlicher Eintrag fehlt")
	}

	// AD-Passwort geändert: gesperrt, bis das alte Passwort eingegeben wird.
	changed, _, err := OpenAD(p, "anna", "neues-pw")
	if err != nil {
		t.Fatal(err)
	}
	if st := changed.PersonalState(); st.Available || !st.Locked {
		t.Fatalf("Zustand nach Passwortwechsel: %+v", st)
	}
	if _, err := changed.SaveEntry(Entry{Title: "x"}, true); !errors.Is(err, ErrPersonalLocked) {
		t.Fatalf("Speichern in gesperrten Tresor: %v", err)
	}
	changed.UpsertEntry(Entry{Title: "gemeinsam trotz Sperre"})
	if err := changed.Save(); err != nil {
		t.Fatal(err)
	}
	if err := changed.UnlockPersonal("falsch"); err == nil {
		t.Fatal("mit falschem altem Passwort entsperrt")
	}
	if err := changed.UnlockPersonal("altes-pw"); err != nil {
		t.Fatal(err)
	}
	after, _, _ := OpenAD(p, "anna", "neues-pw")
	if st := after.PersonalState(); !st.Available || !titles(after.PersonalData())["privat"] {
		t.Fatalf("nach Entsperren mit neuem Passwort: %+v", st)
	}
}
