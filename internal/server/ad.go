package server

import (
	"log"
	"net/http"

	"passmind/internal/vault"
)

func (s *Server) handleGetAD(w http.ResponseWriter, r *http.Request, v *vault.Vault) {
	writeJSON(w, map[string]any{"config": v.ADConfig(), "keyFile": vault.ADKeyPath(v.Path()), "local": !v.IsADUser()})
}

func (s *Server) handleSetAD(w http.ResponseWriter, r *http.Request, v *vault.Vault) {
	var c vault.ADConfig
	if err := readJSON(r, &c); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := v.EnableAD(c); err != nil {
		s.userErr(w, err)
		return
	}
	log.Println("AD-Anmeldung eingerichtet für Gruppe", c.Group)
	writeJSON(w, map[string]any{"config": v.ADConfig(), "keyFile": vault.ADKeyPath(v.Path())})
}

func (s *Server) handleDisableAD(w http.ResponseWriter, r *http.Request, v *vault.Vault) {
	if err := v.DisableAD(); err != nil {
		s.userErr(w, err)
		return
	}
	log.Println("AD-Anmeldung ausgeschaltet")
	writeJSON(w, map[string]bool{"ok": true})
}

// handleTestAD prüft eingegebene AD-Einstellungen mit einem Testkonto, ohne sie zu speichern.
func (s *Server) handleTestAD(w http.ResponseWriter, r *http.Request, v *vault.Vault) {
	var req struct {
		Config   vault.ADConfig `json:"config"`
		User     string         `json:"user"`
		Password string         `json:"password"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !req.Config.Enabled() {
		writeErr(w, http.StatusBadRequest, "Bitte Server, Domäne und Gruppe angeben")
		return
	}
	// Die LDAP-Abfrage kann dauern; die Sperre solange nicht halten.
	s.mu.Unlock()
	name, err := s.adAuth(req.Config, req.User, req.Password)
	s.mu.Lock()
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, map[string]string{"user": name})
}
