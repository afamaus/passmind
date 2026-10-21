package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"passmind/internal/totp"
	"passmind/internal/vault"
)

type client struct {
	t    *testing.T
	base string
	http *http.Client
}

func (c *client) do(method, path string, body any) (int, map[string]any) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.base+path, rd)
	req.Header.Set("X-PS-Request", "1")
	res, err := c.http.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	out := map[string]any{}
	raw, _ := io.ReadAll(res.Body)
	json.Unmarshal(raw, &out)
	if strings.HasPrefix(res.Header.Get("Content-Type"), "text/csv") {
		out["csv"] = string(raw)
	}
	return res.StatusCode, out
}

func startServer(t *testing.T) (*Server, *client, string) {
	path := filepath.Join(t.TempDir(), "test.vault")
	s := New(path, "", fstest.MapFS{"index.html": {Data: []byte("hi")}})
	ln, launch, err := s.Listen("0")
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve(ln)
	t.Cleanup(s.Shutdown)
	jar, _ := cookiejar.New(nil)
	c := &client{t: t, base: "http://" + s.host + "/", http: &http.Client{Jar: jar}}
	return s, c, launch
}

func TestFullFlow(t *testing.T) {
	s, c, launch := startServer(t)

	// Ohne Start-Link gibt es keinen API-Zugriff.
	if code, _ := c.do("GET", "api/status", nil); code != http.StatusUnauthorized {
		t.Fatalf("ohne Cookie: %d", code)
	}
	if _, err := c.http.Get(launch); err != nil {
		t.Fatal(err)
	}
	_, st := c.do("GET", "api/status", nil)
	if st["exists"] != false {
		t.Fatalf("Status: %v", st)
	}

	// Einrichtung mit TOTP
	_, setup := c.do("POST", "api/setup/totp", nil)
	secret := setup["secret"].(string)
	if code, _ := c.do("POST", "api/setup", map[string]string{"user": "rene", "password": "ein-langes-passwort", "code": "000000"}); code != http.StatusBadRequest {
		t.Fatalf("falscher Code akzeptiert: %d", code)
	}
	code6, _ := totp.Code(secret, time.Now())
	code, res := c.do("POST", "api/setup", map[string]string{"user": "rene", "password": "ein-langes-passwort", "code": code6})
	if code != 200 {
		t.Fatalf("Einrichtung: %d %v", code, res)
	}
	recovery := res["recoveryCodes"].([]any)

	// Eintrag anlegen, Liste enthält kein Passwort
	_, e := c.do("POST", "api/entries", map[string]any{"title": "Router", "username": "admin", "password": "s3cret!"})
	id := e["id"].(string)
	_, data := c.do("GET", "api/data", nil)
	if strings.Contains(mustJSON(data), "s3cret!") {
		t.Fatal("Passwort in der Listenansicht")
	}
	_, full := c.do("GET", "api/entries/"+id, nil)
	if full["password"] != "s3cret!" {
		t.Fatalf("Eintrag: %v", full)
	}

	// Sperren, dann Entsperren nur mit Passwort + Code
	c.do("POST", "api/lock", nil)
	if code, _ := c.do("GET", "api/data", nil); code != http.StatusLocked {
		t.Fatalf("gesperrt erwartet: %d", code)
	}
	s.failures = -100 // Wartezeit nach Fehlversuchen im Test abschalten
	if code, _ := c.do("POST", "api/unlock", map[string]string{"user": "rene", "password": "ein-langes-passwort", "code": "123456"}); code != http.StatusUnauthorized {
		t.Fatalf("falscher TOTP-Code akzeptiert: %d", code)
	}
	code, res = c.do("POST", "api/unlock", map[string]string{"password": "ein-langes-passwort", "recoveryCode": recovery[0].(string)})
	if code != 200 || res["recoveryRemaining"] != float64(7) {
		t.Fatalf("Wiederherstellungscode: %d %v", code, res)
	}
	c.do("POST", "api/lock", nil)
	if code, _ := c.do("POST", "api/unlock", map[string]string{"password": "ein-langes-passwort", "recoveryCode": recovery[0].(string)}); code != http.StatusUnauthorized {
		t.Fatal("Wiederherstellungscode doppelt verwendbar")
	}
	code6, _ = totp.Code(secret, time.Now())
	if code, _ := c.do("POST", "api/unlock", map[string]string{"user": "rene", "password": "ein-langes-passwort", "code": code6}); code != 200 {
		t.Fatalf("Entsperren: %d", code)
	}

	// Import und Export
	csv := "PasswordList,Title,UserName,Password,URL,Description\nServer/Linux,web01,root,pw1,https://web01,Prod\n"
	_, imp := c.do("POST", "api/import", map[string]string{"csv": csv})
	if imp["imported"] != float64(1) {
		t.Fatalf("Import: %v", imp)
	}
	if code, _ := c.do("POST", "api/export", map[string]string{"password": "falsch"}); code != http.StatusUnauthorized {
		t.Fatal("Export ohne korrektes Passwort möglich")
	}
	_, exp := c.do("POST", "api/export", map[string]string{"password": "ein-langes-passwort"})
	if !strings.Contains(exp["csv"].(string), "Server/Linux,web01,root,pw1") {
		t.Fatalf("Export: %v", exp["csv"])
	}
}

func TestCSRFAndHost(t *testing.T) {
	_, c, launch := startServer(t)
	c.http.Get(launch)
	req, _ := http.NewRequest("POST", c.base+"api/lock", nil)
	res, _ := c.http.Do(req)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("POST ohne Header: %d", res.StatusCode)
	}
	req, _ = http.NewRequest("GET", c.base+"api/status", nil)
	req.Host = "evil.example:80"
	res, _ = c.http.Do(req)
	if res.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("fremder Host: %d", res.StatusCode)
	}
}

func TestImportFormats(t *testing.T) {
	v := newTestVault()
	r, err := importCSV(v, "\uFEFFOrdner;Titel;Benutzername;Passwort;Tags\nA/B;x;u;p;eins; zwei\n", "")
	if err != nil || r.Imported != 1 {
		t.Fatalf("Semikolon-CSV: %+v %v", r, err)
	}
	if got := strings.Join(v.FolderPath(v.Data.Entries[0].FolderID), "/"); got != "A/B" {
		t.Fatalf("Ordnerpfad %q", got)
	}
	r, err = importCSV(v, "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\nPrivat,,login,Mail,,,,https://mail,me,pw,\n", "")
	if err != nil || r.Imported != 1 {
		t.Fatalf("Bitwarden: %+v %v", r, err)
	}
	e := v.Data.Entries[len(v.Data.Entries)-1]
	if e.Username != "me" || e.Password != "pw" || e.URL != "https://mail" {
		t.Fatalf("Bitwarden-Eintrag: %+v", e)
	}
}

func TestImportKeePass(t *testing.T) {
	v := newTestVault()
	// KeePass 2.x, Export "KeePass CSV (1.x)"
	r, err := importCSV(v, "\"Account\",\"Login Name\",\"Password\",\"Web Site\",\"Comments\"\n\"Mail\",\"rene@example.de\",\"pw\",\"https://mail\",\"Notiz\"\n", "")
	if err != nil || r.Imported != 1 || r.Columns["username"] != "Login Name" {
		t.Fatalf("KeePass 2: %+v %v", r, err)
	}
	e := v.Data.Entries[0]
	if e.Title != "Mail" || e.Username != "rene@example.de" || e.URL != "https://mail" || e.Notes != "Notiz" {
		t.Fatalf("KeePass-2-Eintrag: %+v", e)
	}
	// KeePassXC
	r, err = importCSV(v, "\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\",\"Icon\",\"Last Modified\",\"Created\"\n\"Root/Internet\",\"Forum\",\"rene\",\"pw\",\"\",\"\",\"\",\"0\",\"\",\"\"\n", "")
	if err != nil || r.Imported != 1 {
		t.Fatalf("KeePassXC: %+v %v", r, err)
	}
	e = v.Data.Entries[1]
	if e.Username != "rene" || strings.Join(v.FolderPath(e.FolderID), "/") != "Internet" {
		t.Fatalf("KeePassXC-Eintrag: %+v in %v", e, v.FolderPath(e.FolderID))
	}
	if len(r.Ignored) != 4 {
		t.Fatalf("ignorierte Spalten: %v", r.Ignored)
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func newTestVault() *vault.Vault { return &vault.Vault{} }

func TestSelectAndMoveVault(t *testing.T) {
	s, c, launch := startServer(t)
	c.http.Get(launch)
	dir := t.TempDir()
	s.configPath = filepath.Join(dir, "passmind.json")

	// Ordner auflisten
	if code, l := c.do("GET", "api/fs?path="+dir, nil); code != 200 || l["path"] != dir {
		t.Fatalf("fs: %d %v", code, l)
	}
	// Ordner wählen -> passmind.vault darin
	code, sel := c.do("POST", "api/vault/select", map[string]string{"path": dir})
	if code != 200 || sel["path"] != filepath.Join(dir, "passmind.vault") || sel["exists"] != false {
		t.Fatalf("select: %d %v", code, sel)
	}
	if code, _ := c.do("POST", "api/vault/select", map[string]string{"path": filepath.Join(dir, "gibtsnicht", "x.vault")}); code != http.StatusBadRequest {
		t.Fatal("nicht existierender Ordner akzeptiert")
	}

	// Anlegen und verschieben
	_, setup := c.do("POST", "api/setup/totp", nil)
	code6, _ := totp.Code(setup["secret"].(string), time.Now())
	c.do("POST", "api/setup", map[string]string{"user": "rene", "password": "ein-langes-passwort", "code": code6})
	target := filepath.Join(dir, "nas.vault")
	if code, mv := c.do("POST", "api/vault/move", map[string]string{"path": target}); code != 200 || mv["path"] != target {
		t.Fatalf("move: %d %v", code, mv)
	}
	if LoadConfig(s.configPath).VaultPath != target {
		t.Fatal("Konfiguration merkt sich den neuen Ort nicht")
	}
	if _, st := c.do("GET", "api/status", nil); st["path"] != target {
		t.Fatalf("Status-Pfad: %v", st["path"])
	}
}

func TestMultiUser(t *testing.T) {
	s, c, launch := startServer(t)
	c.http.Get(launch)
	s.failures = -100
	_, setup := c.do("POST", "api/setup/totp", nil)
	code6, _ := totp.Code(setup["secret"].(string), time.Now())
	c.do("POST", "api/setup", map[string]string{"user": "rene", "password": "ein-langes-passwort", "code": code6})

	code, add := c.do("POST", "api/users", map[string]string{"name": "Anna", "role": "user"})
	if code != 200 || add["startPassword"] == nil {
		t.Fatalf("Benutzer anlegen: %d %v", code, add)
	}
	if code, _ := c.do("POST", "api/users", map[string]string{"name": "anna", "role": "user"}); code != http.StatusBadRequest {
		t.Fatal("doppelter Benutzer angelegt")
	}
	c.do("POST", "api/lock", nil)
	_, st := c.do("GET", "api/status", nil)
	if users := st["login"].(map[string]any)["users"].([]any); len(users) != 2 {
		t.Fatalf("Anmeldeliste: %v", st["login"])
	}

	// Erste Anmeldung mit Startpasswort: eigenes Passwort und eigene MFA einrichten.
	code, en := c.do("POST", "api/unlock", map[string]string{"user": "anna", "password": add["startPassword"].(string)})
	if code != 200 || en["enroll"] != true || en["mustChange"] != true || en["secret"] == nil {
		t.Fatalf("Einrichtung erwartet: %d %v", code, en)
	}
	if code, _ := c.do("GET", "api/data", nil); code != http.StatusLocked {
		t.Fatal("vor abgeschlossener Einrichtung schon entsperrt")
	}
	annaCode, _ := totp.Code(en["secret"].(string), time.Now())
	if code, _ := c.do("POST", "api/enroll", map[string]string{"newPassword": "kurz", "code": annaCode}); code != http.StatusBadRequest {
		t.Fatal("zu kurzes Passwort akzeptiert")
	}
	code, done := c.do("POST", "api/enroll", map[string]string{"newPassword": "annas-eigenes-pw", "code": annaCode})
	if code != 200 || len(done["recoveryCodes"].([]any)) != 8 {
		t.Fatalf("Einrichtung: %d %v", code, done)
	}
	_, data := c.do("GET", "api/data", nil)
	if data["user"] != "Anna" || data["role"] != "user" {
		t.Fatalf("angemeldet als %v/%v", data["user"], data["role"])
	}
	if code, _ := c.do("POST", "api/users", map[string]string{"name": "x", "role": "user"}); code != http.StatusForbidden {
		t.Fatal("Nicht-Admin darf Benutzer anlegen")
	}

	// Danach: eigenes Passwort plus eigener Code, Renés Code gilt nicht.
	c.do("POST", "api/lock", nil)
	if code, _ := c.do("POST", "api/unlock", map[string]string{"user": "anna", "password": "annas-eigenes-pw", "code": code6}); code != http.StatusUnauthorized {
		t.Fatal("fremder TOTP-Code akzeptiert")
	}
	annaCode, _ = totp.Code(en["secret"].(string), time.Now())
	if code, _ := c.do("POST", "api/unlock", map[string]string{"user": "anna", "password": "annas-eigenes-pw", "code": annaCode}); code != 200 {
		t.Fatalf("Anna entsperren: %d", code)
	}

	// Admin entfernt Anna.
	c.do("POST", "api/lock", nil)
	code6, _ = totp.Code(setup["secret"].(string), time.Now())
	c.do("POST", "api/unlock", map[string]string{"user": "rene", "password": "ein-langes-passwort", "code": code6})
	if code, _ := c.do("DELETE", "api/users/anna", nil); code != 200 {
		t.Fatalf("Entfernen: %d", code)
	}
	if code, _ := c.do("DELETE", "api/users/rene", nil); code != http.StatusBadRequest {
		t.Fatal("sich selbst entfernt")
	}
	_, list := c.do("GET", "api/users", nil)
	if len(list["users"].([]any)) != 1 {
		t.Fatalf("Benutzerliste: %v", list)
	}
}

func TestBulkEntries(t *testing.T) {
	s, c, launch := startServer(t)
	c.http.Get(launch)
	s.failures = -100
	_, setup := c.do("POST", "api/setup/totp", nil)
	code6, _ := totp.Code(setup["secret"].(string), time.Now())
	c.do("POST", "api/setup", map[string]string{"user": "rene", "password": "ein-langes-passwort", "code": code6})
	_, f := c.do("POST", "api/folders", map[string]string{"name": "Ziel"})
	var ids []string
	for _, title := range []string{"a", "b", "c"} {
		_, e := c.do("POST", "api/entries", map[string]string{"title": title, "password": "x"})
		ids = append(ids, e["id"].(string))
	}
	if code, r := c.do("POST", "api/entries/bulk", map[string]any{"action": "move", "ids": ids[:2], "folderId": f["id"]}); code != 200 || r["count"] != float64(2) {
		t.Fatalf("verschieben: %d %v", code, r)
	}
	if code, _ := c.do("POST", "api/entries/bulk", map[string]any{"action": "move", "ids": ids, "folderId": "gibtsnicht"}); code != http.StatusBadRequest {
		t.Fatal("unbekannter Zielordner akzeptiert")
	}
	if code, r := c.do("POST", "api/entries/bulk", map[string]any{"action": "delete", "ids": ids[1:]}); code != 200 || r["count"] != float64(2) {
		t.Fatalf("löschen: %d %v", code, r)
	}
	_, d := c.do("GET", "api/data", nil)
	entries := d["entries"].([]any)
	if len(entries) != 1 || entries[0].(map[string]any)["folderId"] != f["id"] {
		t.Fatalf("Ergebnis: %v", entries)
	}
}
