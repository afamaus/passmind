package server

import (
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"passmind/internal/vault"
)

const defaultVaultName = "passmind.vault"

// handleListDir liefert Unterordner und Tresordateien eines Ordners für die Ortsauswahl.
func (s *Server) handleListDir(w http.ResponseWriter, r *http.Request) {
	dir := strings.TrimSpace(r.URL.Query().Get("path"))
	if dir == "" {
		s.mu.Lock()
		dir = filepath.Dir(s.vaultPath)
		s.mu.Unlock()
		if st, err := os.Stat(dir); err != nil || !st.IsDir() {
			dir, _ = os.UserHomeDir() // z. B. NAS gerade nicht erreichbar
		}
	}
	dir = filepath.Clean(dir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "Ordner kann nicht gelesen werden: "+dir)
		return
	}
	dirs, vaults := []string{}, []string{}
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		isDir := e.IsDir()
		if e.Type()&os.ModeSymlink != 0 {
			if st, err := os.Stat(filepath.Join(dir, name)); err == nil {
				isDir = st.IsDir()
			}
		}
		switch {
		case isDir:
			dirs = append(dirs, name)
		case strings.HasSuffix(strings.ToLower(name), ".vault"):
			vaults = append(vaults, name)
		}
	}
	sort.Slice(dirs, func(i, j int) bool { return strings.ToLower(dirs[i]) < strings.ToLower(dirs[j]) })
	sort.Strings(vaults)
	parent := filepath.Dir(dir)
	if parent == dir {
		parent = ""
	}
	home, _ := os.UserHomeDir()
	writeJSON(w, map[string]any{
		"path":   dir,
		"parent": parent,
		"sep":    string(filepath.Separator),
		"dirs":   dirs,
		"vaults": vaults,
		"roots":  roots(),
		"home":   home,
	})
}

func roots() []string {
	if runtime.GOOS != "windows" {
		out := []string{"/"}
		for _, p := range []string{"/Volumes", "/media", "/mnt"} {
			if st, err := os.Stat(p); err == nil && st.IsDir() {
				out = append(out, p)
			}
		}
		return out
	}
	var out []string
	for c := 'A'; c <= 'Z'; c++ {
		d := string(c) + `:\`
		if _, err := os.Stat(d); err == nil {
			out = append(out, d)
		}
	}
	return out
}

// resolveVaultPath macht aus einer Eingabe einen absoluten Dateipfad. Ist es ein Ordner,
// wird passmind.vault darin verwendet. Der Ordner muss existieren.
func resolveVaultPath(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", errors.New("Bitte einen Speicherort angeben")
	}
	p, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	if st, err := os.Stat(p); err == nil && st.IsDir() {
		p = filepath.Join(p, defaultVaultName)
	}
	if !strings.HasSuffix(strings.ToLower(p), ".vault") {
		p += ".vault"
	}
	if st, err := os.Stat(filepath.Dir(p)); err != nil || !st.IsDir() {
		return "", errors.New("Der Ordner existiert nicht: " + filepath.Dir(p))
	}
	return p, nil
}

// handleSelectVault wechselt im gesperrten Zustand zu einem anderen (oder neuen) Tresor.
func (s *Server) handleSelectVault(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path string `json:"path"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	p, err := resolveVaultPath(req.Path)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.v != nil {
		writeErr(w, http.StatusConflict, "Bitte zuerst den geöffneten Tresor sperren")
		return
	}
	s.setVaultPathLocked(p)
	writeJSON(w, map[string]any{"path": p, "exists": vault.Exists(p)})
}

// handleMoveVault speichert den geöffneten Tresor an einem neuen Ort.
func (s *Server) handleMoveVault(w http.ResponseWriter, r *http.Request, v *vault.Vault) {
	var req struct {
		Path string `json:"path"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	p, err := resolveVaultPath(req.Path)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	old := v.Path()
	if err := v.MoveTo(p); err != nil {
		s.writeVaultErr(w, err)
		return
	}
	s.setVaultPathLocked(p)
	log.Println("Tresor verschoben nach", p)
	writeJSON(w, map[string]any{"path": p, "oldPath": old})
}

// setVaultPathLocked merkt sich den Tresor-Ort in der Konfiguration; s.mu muss gehalten werden.
func (s *Server) setVaultPathLocked(p string) {
	s.vaultPath = p
	s.pending = nil
	s.cfg.remember(p)
	if err := s.cfg.save(s.configPath); err != nil {
		log.Println("Konfiguration konnte nicht gespeichert werden:", err)
	}
}
