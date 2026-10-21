package server

import (
	"bytes"
	"encoding/csv"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"passmind/internal/vault"
)

// Spaltennamen verschiedener Programme (Passwordstate, KeePass 1.x/2.x, KeePassXC, Bitwarden, eigener Export).
var csvColumns = map[string][]string{
	"folder":   {"folder", "group", "grouping", "passwordlist", "password list", "path", "ordner"},
	"title":    {"title", "name", "account", "titel"},
	"username": {"username", "user name", "login name", "loginname", "login", "login_username", "user", "user_name", "benutzer", "benutzername", "anmeldename"},
	"password": {"password", "login_password", "passwort", "kennwort"},
	"url":      {"url", "web site", "website", "login_uri", "uri", "webseite", "adresse"},
	"notes":    {"notes", "note", "comment", "comments", "notizen"},
	"desc":     {"description", "beschreibung"},
	"tags":     {"tags", "tag"},
}

var tagSplit = regexp.MustCompile(`[,;]`)

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request, v *vault.Vault) {
	var req struct {
		Password string `json:"password"`
		KeyFile  string `json:"keyFile"`
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
	if !s.checkPassword(v, req.Password, kf) {
		writeErr(w, http.StatusUnauthorized, "Passwort oder Schlüsseldatei ist falsch")
		return
	}

	var buf bytes.Buffer
	buf.WriteString("\uFEFF") // BOM, damit Excel UTF-8 erkennt
	cw := csv.NewWriter(&buf)
	cw.Write([]string{"Folder", "Title", "Username", "Password", "URL", "Notes", "Tags"})
	for _, e := range v.Data.Entries {
		cw.Write([]string{
			strings.Join(v.FolderPath(e.FolderID), "/"),
			e.Title, e.Username, e.Password, e.URL, e.Notes, strings.Join(e.Tags, ", "),
		})
	}
	cw.Flush()
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="passmind-export-`+time.Now().Format("2006-01-02")+`.csv"`)
	w.Write(buf.Bytes())
}

func (s *Server) handleImport(w http.ResponseWriter, r *http.Request, v *vault.Vault) {
	var req struct {
		CSV      string `json:"csv"`
		FolderID string `json:"folderId"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := importCSV(v, req.CSV, req.FolderID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.save(w, v) {
		writeJSON(w, res)
	}
}

// importResult meldet, wie viele Einträge übernommen wurden und welche Spalten wohin gingen,
// damit man in der Oberfläche sieht, wenn eine Spalte nicht erkannt wurde.
type importResult struct {
	Imported int               `json:"imported"`
	Columns  map[string]string `json:"columns"` // Feld -> Spaltenname aus der Datei
	Ignored  []string          `json:"ignored"`
}

func importCSV(v *vault.Vault, data, defaultFolder string) (importResult, error) {
	res := importResult{Columns: map[string]string{}, Ignored: []string{}}
	data = strings.TrimPrefix(data, "\uFEFF")
	cr := csv.NewReader(strings.NewReader(data))
	cr.FieldsPerRecord = -1
	cr.LazyQuotes = true
	// Trennzeichen erkennen: deutsches Excel speichert oft mit Semikolon.
	if first, _, _ := strings.Cut(data, "\n"); strings.Count(first, ";") > strings.Count(first, ",") {
		cr.Comma = ';'
	}
	header, err := cr.Read()
	if err != nil {
		return res, errInvalidCSV
	}
	idx := map[string]int{}
	for i, raw := range header {
		h := strings.ToLower(strings.TrimSpace(raw))
		used := false
		for field, names := range csvColumns {
			if _, seen := idx[field]; !seen && slices.Contains(names, h) {
				idx[field] = i
				res.Columns[field] = strings.TrimSpace(raw)
				used = true
			}
		}
		if !used && h != "" {
			res.Ignored = append(res.Ignored, strings.TrimSpace(raw))
		}
	}
	if _, ok := idx["password"]; !ok {
		return res, errNoPasswordColumn
	}
	get := func(rec []string, field string) string {
		i, ok := idx[field]
		if !ok || i >= len(rec) {
			return ""
		}
		return strings.TrimSpace(rec[i])
	}
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return res, errInvalidCSV
		}
		title := get(rec, "title")
		if title == "" {
			title = get(rec, "url")
		}
		if title == "" && get(rec, "password") == "" {
			continue
		}
		if title == "" {
			title = "(ohne Titel)"
		}
		notes := get(rec, "notes")
		if d := get(rec, "desc"); d != "" {
			notes = strings.TrimSpace(d + "\n" + notes)
		}
		folder := defaultFolder
		if p := get(rec, "folder"); p != "" {
			parts := strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' })
			// KeePassXC schreibt die oberste Gruppe "Root" mit, die braucht es hier nicht.
			if len(parts) > 1 && strings.EqualFold(parts[0], "Root") {
				parts = parts[1:]
			}
			folder = v.FolderByPath(parts)
		}
		var tags []string
		for _, t := range tagSplit.Split(get(rec, "tags"), -1) {
			if t = strings.TrimSpace(t); t != "" {
				tags = append(tags, t)
			}
		}
		v.UpsertEntry(vault.Entry{
			FolderID: folder,
			Title:    title,
			Username: get(rec, "username"),
			Password: get(rec, "password"),
			URL:      get(rec, "url"),
			Notes:    notes,
			Tags:     tags,
		})
		res.Imported++
	}
	return res, nil
}

type importError string

func (e importError) Error() string { return string(e) }

const (
	errInvalidCSV       = importError("Die CSV-Datei konnte nicht gelesen werden")
	errNoPasswordColumn = importError("Keine Passwort-Spalte gefunden (erwartet z. B. \"Password\")")
)
