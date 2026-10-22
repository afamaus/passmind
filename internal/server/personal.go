package server

import (
	"errors"
	"net/http"

	"passmind/internal/vault"
)

// handlePersonalUnlock entsperrt den persönlichen Tresor eines AD-Benutzers nach einem
// Wechsel des AD-Passworts mit dem bisherigen Passwort.
func (s *Server) handlePersonalUnlock(w http.ResponseWriter, r *http.Request, v *vault.Vault) {
	var req struct {
		OldPassword string `json:"oldPassword"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := v.UnlockPersonal(req.OldPassword); err != nil {
		if errors.Is(err, vault.ErrBadCredentials) {
			writeErr(w, http.StatusUnauthorized, "Das bisherige Passwort stimmt nicht")
			return
		}
		s.writeVaultErr(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// handlePersonalReset verwirft einen gesperrten persönlichen Tresor.
func (s *Server) handlePersonalReset(w http.ResponseWriter, r *http.Request, v *vault.Vault) {
	if err := v.ResetPersonal(); err != nil {
		s.writeVaultErr(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}
