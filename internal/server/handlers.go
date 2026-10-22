package server

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"slices"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"passmind/internal/gen"
	"passmind/internal/ldapauth"
	"passmind/internal/totp"
	"passmind/internal/vault"
)

const issuer = "PassMind"

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	connErr := ""
	if s.v == nil {
		if err := s.ensureConnectedLocked(s.vaultPath); err != nil {
			connErr = err.Error()
		}
	}
	resp := map[string]any{
		"theme":      s.cfg.Theme,
		"connection": s.connectionInfo(s.vaultPath),
		"connError":  connErr,
		"exists":     vault.Exists(s.vaultPath),
		"unlocked":   s.v != nil,
		"path":       s.vaultPath,
		"recent":     s.cfg.Recent,
	}
	// Früher benutzter Tresor ist nicht erreichbar (z. B. NAS aus): nicht einfach einen neuen anlegen lassen.
	resp["missingKnown"] = !resp["exists"].(bool) && slices.Contains(s.cfg.Recent, s.vaultPath)
	if s.v != nil {
		resp["settings"] = s.v.Data.Settings
		resp["user"] = s.v.User()
	} else if resp["exists"].(bool) {
		info, err := vault.ReadLoginInfo(s.vaultPath)
		if err != nil {
			resp["error"] = err.Error()
		}
		resp["login"] = info
	}
	resp["enrolling"] = s.enroll != nil
	writeJSON(w, resp)
}

// newPendingTOTP erzeugt ein neues TOTP-Geheimnis samt QR-Code; s.mu muss gehalten werden.
func (s *Server) newPendingTOTP(account string) (map[string]any, error) {
	secret := totp.NewSecret()
	if account == "" {
		account = "Tresor"
	}
	uri := totp.URI(secret, issuer, account)
	png, err := qrcode.Encode(uri, qrcode.Medium, 256)
	if err != nil {
		return nil, errors.New("QR-Code konnte nicht erzeugt werden")
	}
	s.pending = &pendingTOTP{secret: secret, created: time.Now()}
	return map[string]any{
		"secret": secret,
		"uri":    uri,
		"qr":     "data:image/png;base64," + base64.StdEncoding.EncodeToString(png),
	}, nil
}

func (s *Server) writePendingTOTP(w http.ResponseWriter, account string) {
	t, err := s.newPendingTOTP(account)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, t)
}

func newMFA(secret string) (vault.MFA, []string) {
	plain, hashes := totp.NewRecoveryCodes(8)
	return vault.MFA{TOTPSecret: secret, RecoveryCodes: hashes}, plain
}

// checkPending prüft den Code gegen das ausstehende TOTP-Geheimnis; s.mu muss gehalten werden.
func (s *Server) checkPending(code string) (string, bool) {
	if s.pending == nil || time.Since(s.pending.created) > 15*time.Minute {
		return "", false
	}
	return s.pending.secret, totp.Verify(s.pending.secret, code, time.Now())
}

func (s *Server) handleSetupTOTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if vault.Exists(s.vaultPath) {
		writeErr(w, http.StatusConflict, "Tresor existiert bereits")
		return
	}
	s.writePendingTOTP(w, r.URL.Query().Get("user"))
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		User     string `json:"user"`
		Password string `json:"password"`
		KeyFile  string `json:"keyFile"`
		Code     string `json:"code"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.User) == "" {
		writeErr(w, http.StatusBadRequest, "Bitte einen Benutzernamen angeben")
		return
	}
	if len([]rune(req.Password)) < 10 {
		writeErr(w, http.StatusBadRequest, "Das Master-Passwort muss mindestens 10 Zeichen lang sein")
		return
	}
	kf, err := decodeKeyFile(req.KeyFile)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if vault.Exists(s.vaultPath) {
		writeErr(w, http.StatusConflict, "Tresor existiert bereits")
		return
	}
	secret, ok := s.checkPending(req.Code)
	if !ok {
		writeErr(w, http.StatusBadRequest, "Der Code aus der Authenticator-App stimmt nicht. Bitte Uhrzeit des Handys prüfen und erneut versuchen.")
		return
	}
	mfa, plain := newMFA(secret)
	v, err := vault.Create(s.vaultPath, req.User, req.Password, kf, mfa)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "Tresor konnte nicht angelegt werden: "+err.Error())
		return
	}
	s.pending = nil
	s.v = v
	s.lastActivity = time.Now()
	s.cfg.remember(s.vaultPath)
	s.cfg.save(s.configPath)
	log.Println("Neuer Tresor angelegt:", s.vaultPath)
	writeJSON(w, map[string]any{"recoveryCodes": plain})
}

func (s *Server) handleNewKeyFile(w http.ResponseWriter, r *http.Request) {
	b := make([]byte, 64)
	rand.Read(b)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="passmind.key"`)
	w.Write(b)
}

func (s *Server) handleUnlock(w http.ResponseWriter, r *http.Request) {
	var req struct {
		User         string `json:"user"`
		Password     string `json:"password"`
		KeyFile      string `json:"keyFile"`
		Code         string `json:"code"`
		RecoveryCode string `json:"recoveryCode"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	kf, err := decodeKeyFile(req.KeyFile)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	s.mu.Lock()
	if s.v != nil {
		s.mu.Unlock()
		writeJSON(w, map[string]any{"ok": true})
		return
	}
	v, mfa, err := s.openFor(strings.TrimSpace(req.User), req.Password, kf)
	if err == nil && (v.MustChange() || mfa == nil) {
		// Erste Anmeldung mit Startpasswort oder MFA vom Admin zurückgesetzt: einrichten lassen.
		s.failures = 0
		if s.enroll != nil {
			s.enroll.Close()
		}
		s.enroll = v
		t, err := s.newPendingTOTP(v.User())
		s.mu.Unlock()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		t["enroll"] = true
		t["mustChange"] = v.MustChange()
		t["user"] = v.User()
		writeJSON(w, t)
		return
	}
	mfaOK, usedRecovery, remaining := false, false, 0
	if err == nil {
		if req.RecoveryCode != "" {
			h := totp.HashRecoveryCode(req.RecoveryCode)
			if i := slices.Index(mfa.RecoveryCodes, h); i >= 0 {
				mfa.RecoveryCodes = slices.Delete(mfa.RecoveryCodes, i, i+1)
				mfaOK, usedRecovery = v.SetMFA(*mfa) == nil, true
			}
		} else {
			mfaOK = totp.Verify(mfa.TOTPSecret, req.Code, time.Now())
		}
		remaining = len(mfa.RecoveryCodes)
	}
	if err != nil || !mfaOK {
		if v != nil {
			v.Close()
		}
		s.failures++
		delay := time.Duration(min(s.failures, 10)) * time.Second
		s.mu.Unlock()
		log.Println("Fehlgeschlagener Entsperrversuch")
		time.Sleep(delay)
		msg := "Anmeldung fehlgeschlagen. Bitte Benutzer, Passwort, Schlüsseldatei und Code prüfen."
		if err != nil && !errors.Is(err, vault.ErrBadCredentials) && !errors.Is(err, ldapauth.ErrBadCredentials) {
			msg = err.Error() // z. B. DC nicht erreichbar, nicht in der Gruppe, AD-Schlüsseldatei fehlt
		}
		writeErr(w, http.StatusUnauthorized, msg)
		return
	}
	s.failures = 0
	s.v = v
	s.lastActivity = time.Now()
	s.cfg.remember(s.vaultPath)
	s.cfg.save(s.configPath)
	s.mu.Unlock()
	log.Println("Angemeldet:", v.User())
	writeJSON(w, map[string]any{"ok": true, "recoveryUsed": usedRecovery, "recoveryRemaining": remaining})
}

// openFor öffnet den Tresor für einen lokalen Benutzer oder, wenn es den Namen lokal nicht gibt
// und die AD-Anmeldung eingerichtet ist, für einen AD-Benutzer (nach LDAP-Prüfung).
func (s *Server) openFor(user, password string, keyFile []byte) (*vault.Vault, *vault.MFA, error) {
	if cfg := vault.ReadADConfig(s.vaultPath); cfg != nil && !s.isLocalUser(user) {
		name, err := s.adAuth(*cfg, user, password)
		if err != nil {
			return nil, nil, err
		}
		return vault.OpenAD(s.vaultPath, name, password)
	}
	return vault.Open(s.vaultPath, user, password, keyFile)
}

func (s *Server) isLocalUser(user string) bool {
	info, err := vault.ReadLoginInfo(s.vaultPath)
	if err != nil {
		return false
	}
	for _, u := range info.Users {
		if strings.EqualFold(u, user) {
			return true
		}
	}
	return false
}

// checkPassword prüft das Passwort des angemeldeten Benutzers erneut (z. B. vor dem Export).
func (s *Server) checkPassword(v *vault.Vault, password string, keyFile []byte) bool {
	if v.IsADUser() {
		cfg := v.ADConfig()
		if cfg == nil {
			return false
		}
		name, err := s.adAuth(*cfg, v.User(), password)
		return err == nil && strings.EqualFold(name, v.User())
	}
	check, _, err := vault.Open(s.vaultPath, v.User(), password, keyFile)
	if err != nil {
		return false
	}
	check.Close()
	return true
}

// handleEnroll schließt die erste Anmeldung ab: eigenes Passwort setzen (bei Startpasswort)
// und Authenticator-App einrichten.
func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NewPassword string `json:"newPassword"`
		Code        string `json:"code"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.enroll
	if v == nil {
		writeErr(w, http.StatusConflict, "Keine Einrichtung offen. Bitte neu anmelden.")
		return
	}
	if v.MustChange() && len([]rune(req.NewPassword)) < 10 {
		writeErr(w, http.StatusBadRequest, "Das neue Passwort muss mindestens 10 Zeichen lang sein")
		return
	}
	secret, ok := s.checkPending(req.Code)
	if !ok {
		writeErr(w, http.StatusBadRequest, "Der Code aus der Authenticator-App stimmt nicht. Bitte Uhrzeit des Handys prüfen und erneut versuchen.")
		return
	}
	if v.MustChange() {
		if err := v.ChangeCredentials(req.NewPassword, nil); err != nil {
			s.writeVaultErr(w, err)
			return
		}
	}
	mfa, plain := newMFA(secret)
	if err := v.SetMFA(mfa); err != nil {
		s.writeVaultErr(w, err)
		return
	}
	s.enroll, s.pending = nil, nil
	s.v = v
	s.lastActivity = time.Now()
	s.cfg.remember(s.vaultPath)
	s.cfg.save(s.configPath)
	log.Println("Benutzer eingerichtet:", v.User())
	writeJSON(w, map[string]any{"recoveryCodes": plain})
}

func (s *Server) handleLock(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.lockLocked()
	s.mu.Unlock()
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleQuit(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]bool{"ok": true})
	go func() {
		time.Sleep(200 * time.Millisecond)
		s.Shutdown()
	}()
}

func (s *Server) handleGenerate(w http.ResponseWriter, r *http.Request) {
	var o gen.Options
	if err := readJSON(r, &o); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := gen.Generate(o)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, res)
}

// entrySummary ist ein Eintrag ohne Passwort und Verlauf für die Listenansicht.
type entrySummary struct {
	ID       string    `json:"id"`
	FolderID string    `json:"folderId"`
	Title    string    `json:"title"`
	Username string    `json:"username"`
	URL      string    `json:"url"`
	Notes    string    `json:"notes"`
	Tags     []string  `json:"tags"`
	Updated  time.Time `json:"updated"`
	Personal bool      `json:"personal,omitempty"`
}

type folderView struct {
	vault.Folder
	Personal bool `json:"personal,omitempty"`
}

func (s *Server) handleData(w http.ResponseWriter, r *http.Request, v *vault.Vault) {
	// Änderungen anderer Geräte (z. B. Tresor auf dem NAS) übernehmen.
	if _, err := v.Refresh(); err != nil {
		s.writeVaultErr(w, err)
		return
	}
	list := make([]entrySummary, 0, len(v.Data.Entries))
	folders := make([]folderView, 0, len(v.Data.Folders))
	add := func(d *vault.Data, personal bool) {
		for _, e := range d.Entries {
			list = append(list, entrySummary{e.ID, e.FolderID, e.Title, e.Username, e.URL, e.Notes, e.Tags, e.Updated, personal})
		}
		for _, f := range d.Folders {
			folders = append(folders, folderView{f, personal})
		}
	}
	add(&v.Data, false)
	if p := v.PersonalData(); p != nil {
		add(p, true)
	}
	writeJSON(w, map[string]any{
		"folders":           folders,
		"entries":           list,
		"personal":          v.PersonalState(),
		"settings":          v.Data.Settings,
		"recoveryRemaining": recoveryLeft(v),
		"keyFileNeeded":     v.KeyFileNeeded(),
		"path":              v.Path(),
		"connection":        s.connectionInfo(v.Path()),
		"user":              v.User(),
		"role":              v.Role(),
		"ad":                v.IsADUser(),
	})
}

func (s *Server) handleGetEntry(w http.ResponseWriter, r *http.Request, v *vault.Vault) {
	e, personal, ok := v.Lookup(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "Eintrag nicht gefunden")
		return
	}
	writeJSON(w, struct {
		vault.Entry
		Personal bool `json:"personal"`
	}{e, personal})
}

func (s *Server) handleSaveEntry(w http.ResponseWriter, r *http.Request, v *vault.Vault) {
	var req struct {
		vault.Entry
		Personal bool `json:"personal"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	e := req.Entry
	e.Title = strings.TrimSpace(e.Title)
	if e.Title == "" {
		writeErr(w, http.StatusBadRequest, "Titel darf nicht leer sein")
		return
	}
	e, err := v.SaveEntry(e, req.Personal)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.save(w, v) {
		return
	}
	writeJSON(w, e)
}

func (s *Server) handleDeleteEntry(w http.ResponseWriter, r *http.Request, v *vault.Vault) {
	if !v.DeleteEntry(r.PathValue("id")) {
		writeErr(w, http.StatusNotFound, "Eintrag nicht gefunden")
		return
	}
	if s.save(w, v) {
		writeJSON(w, map[string]bool{"ok": true})
	}
}

// handleBulkEntries löscht oder verschiebt mehrere Einträge auf einmal (eine Speicherung).
// Verschoben werden kann auch zwischen gemeinsamem und persönlichem Bereich.
func (s *Server) handleBulkEntries(w http.ResponseWriter, r *http.Request, v *vault.Vault) {
	var req struct {
		Action   string   `json:"action"`
		IDs      []string `json:"ids"`
		FolderID string   `json:"folderId"`
		Personal bool     `json:"personal"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.IDs) == 0 {
		writeErr(w, http.StatusBadRequest, "Keine Einträge ausgewählt")
		return
	}
	n := 0
	switch req.Action {
	case "delete":
		for _, id := range req.IDs {
			if v.DeleteEntry(id) {
				n++
			}
		}
	case "move":
		if req.FolderID != "" && !v.FolderExists(req.FolderID, req.Personal) {
			writeErr(w, http.StatusBadRequest, "Zielordner nicht gefunden")
			return
		}
		for _, id := range req.IDs {
			e, personal, ok := v.Lookup(id)
			if !ok || (e.FolderID == req.FolderID && personal == req.Personal) {
				continue
			}
			e.FolderID = req.FolderID
			if _, err := v.SaveEntry(e, req.Personal); err != nil {
				writeErr(w, http.StatusBadRequest, err.Error())
				return
			}
			n++
		}
	default:
		writeErr(w, http.StatusBadRequest, "Unbekannte Aktion")
		return
	}
	if s.save(w, v) {
		writeJSON(w, map[string]int{"count": n})
	}
}

func (s *Server) handleSaveFolder(w http.ResponseWriter, r *http.Request, v *vault.Vault) {
	var req struct {
		vault.Folder
		Personal bool `json:"personal"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	f := req.Folder
	f.Name = strings.TrimSpace(f.Name)
	if f.Name == "" {
		writeErr(w, http.StatusBadRequest, "Name darf nicht leer sein")
		return
	}
	f, err := v.SaveFolder(f, req.Personal)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.save(w, v) {
		writeJSON(w, folderView{f, req.Personal})
	}
}

func (s *Server) handleDeleteFolder(w http.ResponseWriter, r *http.Request, v *vault.Vault) {
	v.DeleteFolder(r.PathValue("id"))
	if s.save(w, v) {
		writeJSON(w, map[string]bool{"ok": true})
	}
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request, v *vault.Vault) {
	var st vault.Settings
	if err := readJSON(r, &st); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if st.AutoLockMinutes < 1 || st.AutoLockMinutes > 240 {
		writeErr(w, http.StatusBadRequest, "Auto-Sperre: 1 bis 240 Minuten")
		return
	}
	if st.ClipboardSeconds < 5 || st.ClipboardSeconds > 600 {
		writeErr(w, http.StatusBadRequest, "Zwischenablage: 5 bis 600 Sekunden")
		return
	}
	st.ChangedAt = time.Now().UTC()
	v.Data.Settings = st
	if s.save(w, v) {
		writeJSON(w, st)
	}
}

func (s *Server) handleCredentials(w http.ResponseWriter, r *http.Request, v *vault.Vault) {
	var req struct {
		CurrentPassword string `json:"currentPassword"`
		CurrentKeyFile  string `json:"currentKeyFile"`
		NewPassword     string `json:"newPassword"`
		NewKeyFile      string `json:"newKeyFile"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	curKF, err := decodeKeyFile(req.CurrentKeyFile)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	newKF, err := decodeKeyFile(req.NewKeyFile)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if len([]rune(req.NewPassword)) < 10 {
		writeErr(w, http.StatusBadRequest, "Das neue Master-Passwort muss mindestens 10 Zeichen lang sein")
		return
	}
	check, _, err := vault.Open(s.vaultPath, v.User(), req.CurrentPassword, curKF)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "Aktuelles Master-Passwort oder Schlüsseldatei ist falsch")
		return
	}
	check.Close()
	if err := v.ChangeCredentials(req.NewPassword, newKF); err != nil {
		s.writeVaultErr(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleMFAReset(w http.ResponseWriter, r *http.Request, v *vault.Vault) {
	var req struct {
		Code string `json:"code"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	m := v.MFA()
	if m == nil || !totp.Verify(m.TOTPSecret, req.Code, time.Now()) {
		writeErr(w, http.StatusUnauthorized, "Aktueller Code ist falsch")
		return
	}
	s.writePendingTOTP(w, v.User())
}

func (s *Server) handleMFAConfirm(w http.ResponseWriter, r *http.Request, v *vault.Vault) {
	var req struct {
		Code string `json:"code"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	secret, ok := s.checkPending(req.Code)
	if !ok {
		writeErr(w, http.StatusBadRequest, "Code stimmt nicht")
		return
	}
	mfa, plain := newMFA(secret)
	if err := v.SetMFA(mfa); err != nil {
		s.writeVaultErr(w, err)
		return
	}
	s.pending = nil
	writeJSON(w, map[string]any{"recoveryCodes": plain})
}

func (s *Server) save(w http.ResponseWriter, v *vault.Vault) bool {
	if err := v.Save(); err != nil {
		s.writeVaultErr(w, err)
		return false
	}
	return true
}

// writeVaultErr meldet einen Speicherfehler. Wurden die Zugangsdaten auf einem anderen
// Gerät geändert, wird der Tresor gesperrt, damit neu entsperrt werden kann; s.mu muss gehalten werden.
func (s *Server) writeVaultErr(w http.ResponseWriter, err error) {
	if errors.Is(err, vault.ErrChangedElsewhere) || errors.Is(err, vault.ErrUserRemoved) {
		s.lockLocked()
		writeErr(w, http.StatusLocked, err.Error())
		return
	}
	writeErr(w, http.StatusInternalServerError, "Speichern fehlgeschlagen: "+err.Error())
}

func recoveryLeft(v *vault.Vault) int {
	if m := v.MFA(); m != nil {
		return len(m.RecoveryCodes)
	}
	return 0
}
