package server

import (
	"errors"
	"log"
	"net/http"

	"passmind/internal/vault"
)

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request, v *vault.Vault) {
	if _, err := v.Refresh(); err != nil {
		s.writeVaultErr(w, err)
		return
	}
	writeJSON(w, map[string]any{"users": v.Users(), "me": v.User(), "admin": v.IsAdmin()})
}

func (s *Server) handleAddUser(w http.ResponseWriter, r *http.Request, v *vault.Vault) {
	var req struct {
		Name string `json:"name"`
		Role string `json:"role"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	pw, err := v.AddUser(req.Name, req.Role)
	if err != nil {
		s.userErr(w, err)
		return
	}
	log.Println("Benutzer angelegt:", req.Name)
	writeJSON(w, map[string]string{"startPassword": pw})
}

func (s *Server) handleResetUser(w http.ResponseWriter, r *http.Request, v *vault.Vault) {
	pw, err := v.ResetUser(r.PathValue("name"))
	if err != nil {
		s.userErr(w, err)
		return
	}
	writeJSON(w, map[string]string{"startPassword": pw})
}

func (s *Server) handleRemoveUser(w http.ResponseWriter, r *http.Request, v *vault.Vault) {
	if err := v.RemoveUser(r.PathValue("name")); err != nil {
		s.userErr(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleSetRole(w http.ResponseWriter, r *http.Request, v *vault.Vault) {
	var req struct {
		Role string `json:"role"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := v.SetRole(r.PathValue("name"), req.Role); err != nil {
		s.userErr(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// userErr meldet einen Fehler der Benutzerverwaltung; s.mu muss gehalten werden.
func (s *Server) userErr(w http.ResponseWriter, err error) {
	if errors.Is(err, vault.ErrChangedElsewhere) || errors.Is(err, vault.ErrUserRemoved) {
		s.writeVaultErr(w, err)
		return
	}
	writeErr(w, http.StatusBadRequest, err.Error())
}
