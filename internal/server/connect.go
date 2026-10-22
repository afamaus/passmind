package server

import (
	"log"
	"net/http"
	"strings"

	"passmind/internal/netshare"
)

// ensureConnectedLocked verbindet die Freigabe eines Pfades mit den gespeicherten Zugangsdaten
// (Verbindungsart „Netzwerk“), einmal pro Programmlauf; s.mu muss gehalten werden.
func (s *Server) ensureConnectedLocked(path string) error {
	share, ok := netshare.ShareRoot(path)
	if !ok || s.connected[strings.ToLower(share)] {
		return nil
	}
	l := s.cfg.shareLogin(share)
	if l == nil {
		return nil
	}
	pw, err := netshare.Unprotect(l.Password)
	if err != nil {
		return errNeedSharePassword(share)
	}
	err = netshare.Connect(share, l.User, string(pw))
	clear(pw)
	if err != nil {
		return err
	}
	s.connected[strings.ToLower(share)] = true
	log.Println("Freigabe verbunden:", share)
	return nil
}

type shareErr struct{ share string }

func (e shareErr) Error() string {
	return "Das gespeicherte Passwort für " + e.share + " kann auf diesem Rechner nicht gelesen werden. Bitte die Netzwerk-Anmeldung neu eingeben."
}

func errNeedSharePassword(share string) error { return shareErr{share} }

// connectionInfo beschreibt, wie ein Tresor-Pfad erreicht wird (für die Oberfläche).
func (s *Server) connectionInfo(path string) map[string]any {
	info := map[string]any{"mode": netshare.ModeDefault, "supported": netshare.Supported}
	if share, ok := netshare.ShareRoot(path); ok {
		info["share"] = share
		if l := s.cfg.shareLogin(share); l != nil {
			info["mode"] = netshare.ModeNetwork
			info["user"] = l.User
		}
	}
	return info
}

// handleConnect verbindet eine Freigabe mit Benutzer und Passwort und merkt sich die Zugangsdaten.
func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path     string `json:"path"`
		User     string `json:"user"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !netshare.Supported {
		writeErr(w, http.StatusBadRequest, netshare.ErrUnsupported.Error())
		return
	}
	share, ok := netshare.ShareRoot(req.Path)
	if !ok {
		writeErr(w, http.StatusBadRequest, `Für die Netzwerk-Anmeldung bitte einen Netzwerkpfad angeben, z. B. \\nas\freigabe\passmind`)
		return
	}
	if strings.TrimSpace(req.User) == "" || req.Password == "" {
		writeErr(w, http.StatusBadRequest, "Bitte Benutzer und Passwort für die Freigabe angeben")
		return
	}
	if err := netshare.Connect(share, strings.TrimSpace(req.User), req.Password); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	blob, err := netshare.Protect([]byte(req.Password))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "Passwort konnte nicht geschützt gespeichert werden: "+err.Error())
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connected[strings.ToLower(share)] = true
	s.cfg.setShareLogin(ShareLogin{Share: share, User: strings.TrimSpace(req.User), Password: blob})
	if err := s.cfg.save(s.configPath); err != nil {
		log.Println("Konfiguration konnte nicht gespeichert werden:", err)
	}
	log.Println("Freigabe verbunden:", share)
	writeJSON(w, map[string]string{"share": share})
}

// handleTheme speichert das gewählte Design in der Konfiguration.
func (s *Server) handleTheme(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Theme string `json:"theme"`
	}
	if err := readJSON(r, &req); err != nil || (req.Theme != "dark" && req.Theme != "light") {
		writeErr(w, http.StatusBadRequest, "Unbekanntes Design")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg.Theme = req.Theme
	if err := s.cfg.save(s.configPath); err != nil {
		writeErr(w, http.StatusInternalServerError, "Einstellung konnte nicht gespeichert werden: "+err.Error())
		return
	}
	writeJSON(w, map[string]string{"theme": req.Theme})
}

// handleThemeJS setzt das gespeicherte Design vor dem ersten Zeichnen (kein Aufblitzen).
func (s *Server) handleThemeJS(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	light := s.cfg.Theme == "light"
	s.mu.Unlock()
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if light {
		w.Write([]byte("document.documentElement.dataset.theme = 'light';\n"))
		return
	}
	w.Write([]byte("// dunkles Design (Standard)\n"))
}
