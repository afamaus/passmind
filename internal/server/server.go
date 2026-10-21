// Package server stellt die Weboberfläche und die JSON-API auf 127.0.0.1 bereit.
package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"passmind/internal/vault"
)

const (
	cookieName  = "ps_session"
	csrfHeader  = "X-PS-Request"
	maxBodySize = 16 << 20
)

// Server hält den Zustand der laufenden Anwendung: einen Tresor und den daran angemeldeten Benutzer.
type Server struct {
	mu           sync.Mutex
	vaultPath    string
	configPath   string
	cfg          Config
	v            *vault.Vault
	lastActivity time.Time
	failures     int
	pending      *pendingTOTP // TOTP-Geheimnis während Einrichtung/Neueinrichtung
	enroll       *vault.Vault // geöffnet, aber erste Anmeldung (Passwort/MFA) noch nicht abgeschlossen

	sessionToken string
	launchToken  string
	host         string // erlaubter Host-Header, z. B. "127.0.0.1:47111"

	static   fs.FS
	Quit     chan struct{}
	quitOnce sync.Once
}

type pendingTOTP struct {
	secret  string
	created time.Time
}

// New erzeugt einen Server für die angegebene Tresordatei. configPath (darf leer sein)
// ist der Ort der passmind.json, in der sich PassMind den gewählten Tresor merkt.
func New(vaultPath, configPath string, static fs.FS) *Server {
	return &Server{
		vaultPath:    vaultPath,
		configPath:   configPath,
		cfg:          LoadConfig(configPath),
		sessionToken: randomToken(),
		launchToken:  randomToken(),
		static:       static,
		Quit:         make(chan struct{}),
	}
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// Listen öffnet den Port auf 127.0.0.1 (0 = beliebiger freier Port) und liefert die Start-URL.
func (s *Server) Listen(port string) (net.Listener, string, error) {
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		return nil, "", err
	}
	s.host = ln.Addr().String()
	return ln, "http://" + s.host + "/launch?t=" + s.launchToken, nil
}

// Serve startet HTTP-Server und Auto-Sperre.
func (s *Server) Serve(ln net.Listener) error {
	go s.autoLockLoop()
	srv := &http.Server{
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-s.Quit
		srv.Close()
	}()
	err := srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Shutdown sperrt den Tresor und beendet den Server.
func (s *Server) Shutdown() {
	s.quitOnce.Do(func() {
		s.mu.Lock()
		s.lockLocked()
		s.mu.Unlock()
		close(s.Quit)
	})
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServerFS(s.static))
	mux.HandleFunc("GET /launch", s.handleLaunch)

	api := http.NewServeMux()
	api.HandleFunc("GET /api/status", s.handleStatus)
	api.HandleFunc("POST /api/setup/totp", s.handleSetupTOTP)
	api.HandleFunc("POST /api/setup", s.handleSetup)
	api.HandleFunc("GET /api/keyfile/new", s.handleNewKeyFile)
	api.HandleFunc("POST /api/unlock", s.handleUnlock)
	api.HandleFunc("POST /api/enroll", s.handleEnroll)
	api.HandleFunc("POST /api/lock", s.handleLock)
	api.HandleFunc("POST /api/quit", s.handleQuit)
	api.HandleFunc("POST /api/generate", s.handleGenerate)
	api.HandleFunc("GET /api/fs", s.handleListDir)
	api.HandleFunc("POST /api/vault/select", s.handleSelectVault)
	api.HandleFunc("POST /api/vault/move", s.unlocked(s.handleMoveVault))
	api.HandleFunc("POST /api/ping", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, map[string]bool{"ok": true}) })

	api.HandleFunc("GET /api/data", s.unlocked(s.handleData))
	api.HandleFunc("GET /api/entries/{id}", s.unlocked(s.handleGetEntry))
	api.HandleFunc("POST /api/entries", s.unlocked(s.handleSaveEntry))
	api.HandleFunc("DELETE /api/entries/{id}", s.unlocked(s.handleDeleteEntry))
	api.HandleFunc("POST /api/entries/bulk", s.unlocked(s.handleBulkEntries))
	api.HandleFunc("POST /api/folders", s.unlocked(s.handleSaveFolder))
	api.HandleFunc("DELETE /api/folders/{id}", s.unlocked(s.handleDeleteFolder))
	api.HandleFunc("PUT /api/settings", s.unlocked(s.handleSettings))
	api.HandleFunc("POST /api/credentials", s.unlocked(s.handleCredentials))
	api.HandleFunc("POST /api/mfa/reset", s.unlocked(s.handleMFAReset))
	api.HandleFunc("POST /api/mfa/confirm", s.unlocked(s.handleMFAConfirm))
	api.HandleFunc("POST /api/export", s.unlocked(s.handleExport))
	api.HandleFunc("POST /api/import", s.unlocked(s.handleImport))
	api.HandleFunc("GET /api/users", s.unlocked(s.handleUsers))
	api.HandleFunc("POST /api/users", s.admin(s.handleAddUser))
	api.HandleFunc("DELETE /api/users/{name}", s.admin(s.handleRemoveUser))
	api.HandleFunc("POST /api/users/{name}/reset", s.admin(s.handleResetUser))
	api.HandleFunc("PUT /api/users/{name}/role", s.admin(s.handleSetRole))

	mux.Handle("/api/", s.apiGuard(api))
	return s.securityHeaders(mux)
}

// securityHeaders prüft den Host-Header (Schutz gegen DNS-Rebinding) und setzt Sicherheits-Header.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != s.host && r.Host != strings.Replace(s.host, "127.0.0.1", "localhost", 1) {
			http.Error(w, "ungültiger Host", http.StatusMisdirectedRequest)
			return
		}
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'; form-action 'self'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// apiGuard verlangt das Sitzungs-Cookie und bei schreibenden Anfragen einen eigenen Header (CSRF-Schutz).
func (s *Server) apiGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		if err != nil || subtle.ConstantTimeCompare([]byte(c.Value), []byte(s.sessionToken)) != 1 {
			writeErr(w, http.StatusUnauthorized, "Sitzung ungültig. Bitte das Programm neu starten oder die Start-Adresse aus dem Konsolenfenster öffnen.")
			return
		}
		if r.Method != http.MethodGet && r.Header.Get(csrfHeader) != "1" {
			writeErr(w, http.StatusForbidden, "Anfrage abgelehnt")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
		if r.URL.Path != "/api/status" {
			s.mu.Lock()
			s.lastActivity = time.Now()
			s.mu.Unlock()
		}
		next.ServeHTTP(w, r)
	})
}

// unlocked lässt die Anfrage nur durch, wenn der Tresor entsperrt ist, und hält dabei die Sperre.
func (s *Server) unlocked(h func(http.ResponseWriter, *http.Request, *vault.Vault)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.v == nil {
			writeErr(w, http.StatusLocked, "Tresor ist gesperrt")
			return
		}
		h(w, r, s.v)
	}
}

// admin wie unlocked, aber nur für Admins des Tresors.
func (s *Server) admin(h func(http.ResponseWriter, *http.Request, *vault.Vault)) http.HandlerFunc {
	return s.unlocked(func(w http.ResponseWriter, r *http.Request, v *vault.Vault) {
		if !v.IsAdmin() {
			writeErr(w, http.StatusForbidden, "Nur Admins dürfen Benutzer verwalten")
			return
		}
		h(w, r, v)
	})
}

func (s *Server) handleLaunch(w http.ResponseWriter, r *http.Request) {
	if subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("t")), []byte(s.launchToken)) != 1 {
		http.Error(w, "Ungültiger Startlink. Bitte die Adresse aus dem Konsolenfenster verwenden.", http.StatusForbidden)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    s.sessionToken,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) autoLockLoop() {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.Quit:
			return
		case <-t.C:
			s.mu.Lock()
			if s.v != nil {
				limit := time.Duration(s.v.Data.Settings.AutoLockMinutes) * time.Minute
				if limit > 0 && time.Since(s.lastActivity) > limit {
					log.Println("Tresor wegen Inaktivität gesperrt")
					s.lockLocked()
				}
			}
			s.mu.Unlock()
		}
	}
}

// lockLocked sperrt den Tresor; s.mu muss gehalten werden.
func (s *Server) lockLocked() {
	if s.v != nil {
		s.v.Close()
		s.v = nil
	}
	if s.enroll != nil {
		s.enroll.Close()
		s.enroll = nil
	}
	s.pending = nil
}

func readJSON(r *http.Request, v any) error {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		return errors.New("ungültige Anfrage")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func decodeKeyFile(b64 string) ([]byte, error) {
	if b64 == "" {
		return nil, nil
	}
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(b) == 0 {
		return nil, errors.New("Schlüsseldatei konnte nicht gelesen werden")
	}
	return b, nil
}
