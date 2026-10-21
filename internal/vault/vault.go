package vault

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// Folder entspricht einem Ordner bzw. einer Passwortliste in der Baumansicht.
type Folder struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	ParentID string    `json:"parentId,omitempty"`
	Updated  time.Time `json:"updated,omitempty"`
}

// HistoryItem hält ein früheres Passwort eines Eintrags fest.
type HistoryItem struct {
	Password  string    `json:"password"`
	ChangedAt time.Time `json:"changedAt"`
}

// Entry ist ein einzelner Passwort-Eintrag.
type Entry struct {
	ID       string        `json:"id"`
	FolderID string        `json:"folderId,omitempty"`
	Title    string        `json:"title"`
	Username string        `json:"username"`
	Password string        `json:"password"`
	URL      string        `json:"url"`
	Notes    string        `json:"notes"`
	Tags     []string      `json:"tags"`
	Created  time.Time     `json:"created"`
	Updated  time.Time     `json:"updated"`
	History  []HistoryItem `json:"history,omitempty"`
}

// MFA enthält das TOTP-Geheimnis und die gehashten Wiederherstellungscodes.
type MFA struct {
	TOTPSecret    string    `json:"totpSecret"`
	RecoveryCodes []string  `json:"recoveryCodes"` // SHA-256 als Hex
	ChangedAt     time.Time `json:"changedAt,omitempty"`
}

// Settings sind Benutzereinstellungen, die mit im Tresor gespeichert werden.
type Settings struct {
	AutoLockMinutes  int       `json:"autoLockMinutes"`
	ClipboardSeconds int       `json:"clipboardSeconds"`
	ChangedAt        time.Time `json:"changedAt,omitempty"`
}

// Tombstone merkt sich gelöschte Einträge und Ordner, damit das Zusammenführen
// mit einer auf einem anderen Gerät geänderten Fassung sie nicht wieder auferstehen lässt.
type Tombstone struct {
	ID string    `json:"id"`
	At time.Time `json:"at"`
}

// Data ist der komplette entschlüsselte Inhalt des Tresors.
type Data struct {
	Folders  []Folder    `json:"folders"`
	Entries  []Entry     `json:"entries"`
	MFA      MFA         `json:"mfa"`
	Settings Settings    `json:"settings"`
	Deleted  []Tombstone `json:"deleted,omitempty"`
}

// Vault ist ein geöffneter (entschlüsselter) Tresor.
type Vault struct {
	path          string
	key           []byte
	kdf           KDFParams
	keyFileNeeded bool
	lastHash      [32]byte // Hash der Datei, wie wir sie zuletzt gelesen oder geschrieben haben
	Data          Data
}

const maxHistory = 20

// NewID erzeugt eine zufällige ID für Ordner und Einträge.
func NewID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Exists meldet, ob unter path bereits ein Tresor liegt.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// NeedsKeyFile liest den Tresorkopf und meldet, ob eine Schlüsseldatei verlangt wird.
func NeedsKeyFile(path string) (bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	h, _, err := readHeader(raw)
	return h.KeyFileNeeded, err
}

// Create legt einen neuen Tresor an und speichert ihn sofort.
func Create(path, password string, keyFile []byte, mfa MFA) (*Vault, error) {
	if Exists(path) {
		return nil, errors.New("an diesem Ort existiert bereits ein Tresor")
	}
	kdf, err := defaultKDF()
	if err != nil {
		return nil, err
	}
	key, err := deriveKey(password, keyFile, kdf)
	if err != nil {
		return nil, err
	}
	v := &Vault{
		path:          path,
		key:           key,
		kdf:           kdf,
		keyFileNeeded: len(keyFile) > 0,
		Data: Data{
			Folders:  []Folder{{ID: NewID(), Name: "Allgemein"}},
			Entries:  []Entry{},
			MFA:      mfa,
			Settings: Settings{AutoLockMinutes: 5, ClipboardSeconds: 20},
		},
	}
	return v, v.Save()
}

// Open entschlüsselt einen vorhandenen Tresor.
func Open(path, password string, keyFile []byte) (*Vault, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pt, key, h, err := open(raw, password, keyFile)
	if err != nil {
		return nil, err
	}
	v := &Vault{path: path, key: key, kdf: h.KDF, keyFileNeeded: h.KeyFileNeeded, lastHash: sha256.Sum256(raw)}
	if err := json.Unmarshal(pt, &v.Data); err != nil {
		return nil, errors.New("Tresorinhalt ist beschädigt")
	}
	clear(pt)
	if v.Data.Settings.AutoLockMinutes == 0 {
		v.Data.Settings.AutoLockMinutes = 5
	}
	if v.Data.Settings.ClipboardSeconds == 0 {
		v.Data.Settings.ClipboardSeconds = 20
	}
	return v, nil
}

// Save verschlüsselt den Tresor und schreibt ihn atomar. Hat ein anderes Gerät die Datei
// inzwischen geändert (z. B. auf einem NAS), werden dessen Änderungen vorher übernommen.
// Die vorherige Fassung bleibt als .bak erhalten.
func (v *Vault) Save() error {
	if _, err := v.Refresh(); err != nil {
		return err
	}
	return v.write()
}

func (v *Vault) write() error {
	pt, err := json.Marshal(v.Data)
	if err != nil {
		return err
	}
	out, err := seal(v.key, pt, v.keyFileNeeded, v.kdf)
	clear(pt)
	if err != nil {
		return err
	}
	dir := filepath.Dir(v.path)
	tmp, err := os.CreateTemp(dir, ".vault-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(out); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if Exists(v.path) {
		if old, err := os.ReadFile(v.path); err == nil {
			_ = os.WriteFile(v.path+".bak", old, 0o600)
		}
	}
	if err := os.Rename(tmpName, v.path); err != nil {
		return err
	}
	v.lastHash = sha256.Sum256(out)
	return nil
}

// Path liefert den Speicherort der Tresordatei.
func (v *Vault) Path() string { return v.path }

// MoveTo speichert den Tresor an einem neuen Ort und arbeitet ab dann dort weiter.
// Die alte Datei bleibt unverändert liegen.
func (v *Vault) MoveTo(path string) error {
	if Exists(path) {
		return errors.New("am Zielort existiert bereits eine Datei")
	}
	if _, err := v.Refresh(); err != nil {
		return err
	}
	old := v.path
	v.path = path
	if err := v.write(); err != nil {
		v.path = old
		return err
	}
	return nil
}

// ChangeCredentials setzt ein neues Master-Passwort und/oder eine neue Schlüsseldatei (nil = keine).
func (v *Vault) ChangeCredentials(password string, keyFile []byte) error {
	kdf, err := defaultKDF()
	if err != nil {
		return err
	}
	key, err := deriveKey(password, keyFile, kdf)
	if err != nil {
		return err
	}
	// Änderungen anderer Geräte noch mit dem alten Schlüssel übernehmen, dann neu verschlüsseln.
	if _, err := v.Refresh(); err != nil {
		return err
	}
	oldKey, oldKDF, oldKF := v.key, v.kdf, v.keyFileNeeded
	v.key, v.kdf, v.keyFileNeeded = key, kdf, len(keyFile) > 0
	if err := v.write(); err != nil {
		v.key, v.kdf, v.keyFileNeeded = oldKey, oldKDF, oldKF
		return err
	}
	clear(oldKey)
	return nil
}

// KeyFileNeeded meldet, ob dieser Tresor mit einer Schlüsseldatei geschützt ist.
func (v *Vault) KeyFileNeeded() bool { return v.keyFileNeeded }

// Close entfernt den Schlüssel aus dem Speicher.
func (v *Vault) Close() {
	clear(v.key)
	v.key = nil
	v.Data = Data{}
}

// UpsertEntry legt einen Eintrag an oder aktualisiert ihn und führt den Passwortverlauf.
func (v *Vault) UpsertEntry(e Entry) Entry {
	now := time.Now().UTC()
	if e.Tags == nil {
		e.Tags = []string{}
	}
	for i := range v.Data.Entries {
		old := &v.Data.Entries[i]
		if old.ID != e.ID {
			continue
		}
		e.Created = old.Created
		e.History = old.History
		if old.Password != e.Password && old.Password != "" {
			e.History = append([]HistoryItem{{Password: old.Password, ChangedAt: now}}, e.History...)
			if len(e.History) > maxHistory {
				e.History = e.History[:maxHistory]
			}
		}
		e.Updated = now
		*old = e
		return e
	}
	e.ID = NewID()
	e.Created, e.Updated = now, now
	e.History = nil
	v.Data.Entries = append(v.Data.Entries, e)
	return e
}

// DeleteEntry entfernt einen Eintrag.
func (v *Vault) DeleteEntry(id string) bool {
	for i, e := range v.Data.Entries {
		if e.ID == id {
			v.Data.Entries = append(v.Data.Entries[:i], v.Data.Entries[i+1:]...)
			v.tombstone(id)
			return true
		}
	}
	return false
}

// Entry sucht einen Eintrag per ID.
func (v *Vault) Entry(id string) (Entry, bool) {
	for _, e := range v.Data.Entries {
		if e.ID == id {
			return e, true
		}
	}
	return Entry{}, false
}

// UpsertFolder legt einen Ordner an oder benennt ihn um / verschiebt ihn.
func (v *Vault) UpsertFolder(f Folder) (Folder, error) {
	if f.ParentID != "" {
		if !v.folderExists(f.ParentID) {
			return f, errors.New("übergeordneter Ordner existiert nicht")
		}
		// Zyklen verhindern: der neue Elternordner darf nicht unterhalb von f liegen.
		for p := f.ParentID; p != ""; p = v.parentOf(p) {
			if p == f.ID {
				return f, errors.New("ein Ordner kann nicht in sich selbst verschoben werden")
			}
		}
	}
	f.Updated = time.Now().UTC()
	for i := range v.Data.Folders {
		if v.Data.Folders[i].ID == f.ID {
			v.Data.Folders[i] = f
			return f, nil
		}
	}
	f.ID = NewID()
	v.Data.Folders = append(v.Data.Folders, f)
	return f, nil
}

// DeleteFolder löscht einen Ordner samt Unterordnern und Einträgen.
func (v *Vault) DeleteFolder(id string) {
	doomed := map[string]bool{id: true}
	for changed := true; changed; {
		changed = false
		for _, f := range v.Data.Folders {
			if !doomed[f.ID] && doomed[f.ParentID] {
				doomed[f.ID] = true
				changed = true
			}
		}
	}
	folders := v.Data.Folders[:0]
	for _, f := range v.Data.Folders {
		if !doomed[f.ID] {
			folders = append(folders, f)
		} else {
			v.tombstone(f.ID)
		}
	}
	v.Data.Folders = folders
	entries := v.Data.Entries[:0]
	for _, e := range v.Data.Entries {
		if !doomed[e.FolderID] {
			entries = append(entries, e)
		} else {
			v.tombstone(e.ID)
		}
	}
	v.Data.Entries = entries
}

// FolderByPath sucht oder erstellt einen Ordnerpfad wie "Server/Linux" (für den Import).
func (v *Vault) FolderByPath(parts []string) string {
	parent := ""
	for _, name := range parts {
		if name == "" {
			continue
		}
		found := ""
		for _, f := range v.Data.Folders {
			if f.ParentID == parent && f.Name == name {
				found = f.ID
				break
			}
		}
		if found == "" {
			f, _ := v.UpsertFolder(Folder{Name: name, ParentID: parent})
			found = f.ID
		}
		parent = found
	}
	return parent
}

// FolderPath liefert den Pfad eines Ordners als Namensliste (für den Export).
func (v *Vault) FolderPath(id string) []string {
	var parts []string
	for p := id; p != ""; p = v.parentOf(p) {
		for _, f := range v.Data.Folders {
			if f.ID == p {
				parts = append([]string{f.Name}, parts...)
			}
		}
		if len(parts) > 64 {
			break
		}
	}
	return parts
}

func (v *Vault) folderExists(id string) bool {
	for _, f := range v.Data.Folders {
		if f.ID == id {
			return true
		}
	}
	return false
}

func (v *Vault) parentOf(id string) string {
	for _, f := range v.Data.Folders {
		if f.ID == id {
			return f.ParentID
		}
	}
	return ""
}
