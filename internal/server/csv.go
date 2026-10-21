package server

import (
	"bytes"
	"encoding/csv"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"passmind/internal/vault"
)

// Spaltennamen verschiedener Programme (Passwordstate, KeePass, Bitwarden, eigener Export).
var csvColumns = map[string][]string{
	"folder":   {"folder", "group", "grouping", "passwordlist", "password list", "path", "ordner"},
	"title":    {"title", "name", "account", "titel"},
	"username": {"username", "user name", "login", "login_username", "user", "benutzer", "benutzername"},
	"password": {"password", "login_password", "passwort", "kennwort"},
	"url":      {"url", "web site", "website", "login_uri", "uri"},
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
	check, _, err := vault.Open(s.vaultPath, v.User(), req.Password, kf)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "Passwort oder Schlüsseldatei ist falsch")
		return
	}
	check.Close()

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
	n, err := importCSV(v, req.CSV, req.FolderID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.save(w, v) {
		writeJSON(w, map[string]int{"imported": n})
	}
}

func importCSV(v *vault.Vault, data, defaultFolder string) (int, error) {
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
		return 0, errInvalidCSV
	}
	idx := map[string]int{}
	for i, h := range header {
		h = strings.ToLower(strings.TrimSpace(h))
		for field, names := range csvColumns {
			for _, n := range names {
				if h == n {
					if _, seen := idx[field]; !seen {
						idx[field] = i
					}
				}
			}
		}
	}
	if _, ok := idx["password"]; !ok {
		return 0, errNoPasswordColumn
	}
	get := func(rec []string, field string) string {
		i, ok := idx[field]
		if !ok || i >= len(rec) {
			return ""
		}
		return strings.TrimSpace(rec[i])
	}
	count := 0
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return count, errInvalidCSV
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
			folder = v.FolderByPath(strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' }))
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
		count++
	}
	return count, nil
}

type importError string

func (e importError) Error() string { return string(e) }

const (
	errInvalidCSV       = importError("Die CSV-Datei konnte nicht gelesen werden")
	errNoPasswordColumn = importError("Keine Passwort-Spalte gefunden (erwartet z. B. \"Password\")")
)
