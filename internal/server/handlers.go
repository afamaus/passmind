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
	"passmind/internal/totp"
	"passmind/internal/vault"
)

const issuer = "PassMind"

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	resp := map[string]any{
		"exists":   vault.Exists(s.vaultPath),
		"unlocked": s.v != nil,
		"path":     s.vaultPath,
		"recent":   s.cfg.Recent,
	}
	// Früher benutzter Tresor ist nicht erreichbar (z. B. NAS aus): nicht einfach einen neuen anlegen lassen.
	resp["missingKnown"] = !resp["exists"].(bool) && slices.Contains(s.cfg.Recent, s.vaultPath)
	if s.v != nil {
		resp["settings"] = s.v.Data.Settings
		resp["keyFileNeeded"] = s.v.KeyFileNeeded()
	} else if resp["exists"].(bool) {
		kf, err := vault.NeedsKeyFile(s.vaultPath)
		if err != nil {
			resp["error"] = err.Error()
		}
		resp["keyFileNeeded"] = kf
	}
	writeJSON(w, resp)
}

// newPendingTOTP erzeugt ein neues TOTP-Geheimnis samt QR-Code; s.mu muss gehalten werden.
func (s *Server) newPendingTOTP(w http.ResponseWriter) {
	secret := totp.NewSecret()
	uri := totp.URI(secret, issuer, "Tresor")
	png, err := qrcode.Encode(uri, qrcode.Medium, 256)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "QR-Code konnte nicht erzeugt werden")
		return
	}
	s.pending = &pendingTOTP{secret: secret, created: time.Now()}
	writeJSON(w, map[string]string{
		"secret": secret,
		"uri":    uri,
		"qr":     "data:image/png;base64," + base64.StdEncoding.EncodeToString(png),
	})
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
	s.newPendingTOTP(w)
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
		KeyFile  string `json:"keyFile"`
		Code     string `json:"code"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
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
	plain, hashes := totp.NewRecoveryCodes(8)
	v, err := vault.Create(s.vaultPath, req.Password, kf, vault.MFA{TOTPSecret: secret, RecoveryCodes: hashes, ChangedAt: time.Now().UTC()})
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
	v, err := vault.Open(s.vaultPath, req.Password, kf)
	mfaOK, usedRecovery := false, false
	if err == nil {
		if req.RecoveryCode != "" {
			h := totp.HashRecoveryCode(req.RecoveryCode)
			if i := slices.Index(v.Data.MFA.RecoveryCodes, h); i >= 0 {
				v.Data.MFA.RecoveryCodes = slices.Delete(v.Data.MFA.RecoveryCodes, i, i+1)
				v.Data.MFA.ChangedAt = time.Now().UTC()
				mfaOK, usedRecovery = v.Save() == nil, true
			}
		} else {
			mfaOK = totp.Verify(v.Data.MFA.TOTPSecret, req.Code, time.Now())
		}
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
		writeErr(w, http.StatusUnauthorized, "Anmeldung fehlgeschlagen. Bitte Master-Passwort, Schlüsseldatei und Code prüfen.")
		return
	}
	s.failures = 0
	s.v = v
	s.lastActivity = time.Now()
	s.cfg.remember(s.vaultPath)
	s.cfg.save(s.configPath)
	remaining := len(v.Data.MFA.RecoveryCodes)
	s.mu.Unlock()
	writeJSON(w, map[string]any{"ok": true, "recoveryUsed": usedRecovery, "recoveryRemaining": remaining})
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
}

func (s *Server) handleData(w http.ResponseWriter, r *http.Request, v *vault.Vault) {
	// Änderungen anderer Geräte (z. B. Tresor auf dem NAS) übernehmen.
	if _, err := v.Refresh(); err != nil {
		s.writeVaultErr(w, err)
		return
	}
	list := make([]entrySummary, 0, len(v.Data.Entries))
	for _, e := range v.Data.Entries {
		list = append(list, entrySummary{e.ID, e.FolderID, e.Title, e.Username, e.URL, e.Notes, e.Tags, e.Updated})
	}
	writeJSON(w, map[string]any{
		"folders":           v.Data.Folders,
		"entries":           list,
		"settings":          v.Data.Settings,
		"recoveryRemaining": len(v.Data.MFA.RecoveryCodes),
		"keyFileNeeded":     v.KeyFileNeeded(),
		"path":              v.Path(),
	})
}

func (s *Server) handleGetEntry(w http.ResponseWriter, r *http.Request, v *vault.Vault) {
	e, ok := v.Entry(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "Eintrag nicht gefunden")
		return
	}
	writeJSON(w, e)
}

func (s *Server) handleSaveEntry(w http.ResponseWriter, r *http.Request, v *vault.Vault) {
	var e vault.Entry
	if err := readJSON(r, &e); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	e.Title = strings.TrimSpace(e.Title)
	if e.Title == "" {
		writeErr(w, http.StatusBadRequest, "Titel darf nicht leer sein")
		return
	}
	e = v.UpsertEntry(e)
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

func (s *Server) handleSaveFolder(w http.ResponseWriter, r *http.Request, v *vault.Vault) {
	var f vault.Folder
	if err := readJSON(r, &f); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	f.Name = strings.TrimSpace(f.Name)
	if f.Name == "" {
		writeErr(w, http.StatusBadRequest, "Name darf nicht leer sein")
		return
	}
	f, err := v.UpsertFolder(f)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.save(w, v) {
		writeJSON(w, f)
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
	check, err := vault.Open(s.vaultPath, req.CurrentPassword, curKF)
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
	if !totp.Verify(v.Data.MFA.TOTPSecret, req.Code, time.Now()) {
		writeErr(w, http.StatusUnauthorized, "Aktueller Code ist falsch")
		return
	}
	s.newPendingTOTP(w)
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
	plain, hashes := totp.NewRecoveryCodes(8)
	old := v.Data.MFA
	v.Data.MFA = vault.MFA{TOTPSecret: secret, RecoveryCodes: hashes, ChangedAt: time.Now().UTC()}
	if err := v.Save(); err != nil {
		v.Data.MFA = old
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
	if errors.Is(err, vault.ErrChangedElsewhere) {
		s.lockLocked()
		writeErr(w, http.StatusLocked, err.Error())
		return
	}
	writeErr(w, http.StatusInternalServerError, "Speichern fehlgeschlagen: "+err.Error())
}
