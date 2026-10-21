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
	s := New(path, fstest.MapFS{"index.html": {Data: []byte("hi")}})
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
	if code, _ := c.do("POST", "api/setup", map[string]string{"password": "ein-langes-passwort", "code": "000000"}); code != http.StatusBadRequest {
		t.Fatalf("falscher Code akzeptiert: %d", code)
	}
	code6, _ := totp.Code(secret, time.Now())
	code, res := c.do("POST", "api/setup", map[string]string{"password": "ein-langes-passwort", "code": code6})
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
	if code, _ := c.do("POST", "api/unlock", map[string]string{"password": "ein-langes-passwort", "code": "123456"}); code != http.StatusUnauthorized {
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
	if code, _ := c.do("POST", "api/unlock", map[string]string{"password": "ein-langes-passwort", "code": code6}); code != 200 {
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
	n, err := importCSV(v, "\uFEFFOrdner;Titel;Benutzername;Passwort;Tags\nA/B;x;u;p;eins; zwei\n", "")
	if err != nil || n != 1 {
		t.Fatalf("Semikolon-CSV: %d %v", n, err)
	}
	if got := strings.Join(v.FolderPath(v.Data.Entries[0].FolderID), "/"); got != "A/B" {
		t.Fatalf("Ordnerpfad %q", got)
	}
	n, err = importCSV(v, "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\nPrivat,,login,Mail,,,,https://mail,me,pw,\n", "")
	if err != nil || n != 1 {
		t.Fatalf("Bitwarden: %d %v", n, err)
	}
	e := v.Data.Entries[len(v.Data.Entries)-1]
	if e.Username != "me" || e.Password != "pw" || e.URL != "https://mail" {
		t.Fatalf("Bitwarden-Eintrag: %+v", e)
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func newTestVault() *vault.Vault { return &vault.Vault{} }
