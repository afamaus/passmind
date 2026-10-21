package vault

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	ID        string        `json:"id"`
	FolderID  string        `json:"folderId,omitempty"`
	Title     string        `json:"title"`
	Username  string        `json:"username"`
	Password  string        `json:"password"`
	URL       string        `json:"url"`
	Notes     string        `json:"notes"`
	Tags      []string      `json:"tags"`
	Created   time.Time     `json:"created"`
	Updated   time.Time     `json:"updated"`
	UpdatedBy string        `json:"updatedBy,omitempty"`
	History   []HistoryItem `json:"history,omitempty"`
}

// MFA enthält das TOTP-Geheimnis und die gehashten Wiederherstellungscodes eines Benutzers.
// Sie liegen verschlüsselt im Slot des Benutzers, nicht in den gemeinsamen Daten.
type MFA struct {
	TOTPSecret    string    `json:"totpSecret"`
	RecoveryCodes []string  `json:"recoveryCodes"` // SHA-256 als Hex
	ChangedAt     time.Time `json:"changedAt,omitempty"`
}

// Settings sind Einstellungen, die mit im Tresor gespeichert werden.
type Settings struct {
	AutoLockMinutes  int       `json:"autoLockMinutes"`
	ClipboardSeconds int       `json:"clipboardSeconds"`
	ChangedAt        time.Time `json:"changedAt,omitempty"`
}

// Tombstone merkt sich gelöschte Einträge, Ordner und Benutzer, damit das Zusammenführen
// mit einer auf einem anderen Gerät geänderten Fassung sie nicht wieder auferstehen lässt.
type Tombstone struct {
	ID string    `json:"id"`
	At time.Time `json:"at"`
}

// Rollen
const (
	RoleAdmin = "admin"
	RoleUser  = "user"
)

// UserInfo sind die für alle sichtbaren Angaben zu einem Benutzer.
type UserInfo struct {
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	Created   time.Time `json:"created"`
	ChangedAt time.Time `json:"changedAt"`
	AD        bool      `json:"ad,omitempty"`  // meldet sich über Active Directory an
	MFA       *MFA      `json:"mfa,omitempty"` // nur AD-Benutzer: ihre MFA (lokale Benutzer haben sie im Slot)
}

// Data ist der komplette entschlüsselte, gemeinsame Inhalt des Tresors.
type Data struct {
	Folders   []Folder    `json:"folders"`
	Entries   []Entry     `json:"entries"`
	Users     []UserInfo  `json:"users"`
	Settings  Settings    `json:"settings"`
	Deleted   []Tombstone `json:"deleted,omitempty"`
	LegacyMFA *MFA        `json:"mfa,omitempty"` // nur Format 1
}

// Vault ist ein für einen Benutzer geöffneter (entschlüsselter) Tresor.
type Vault struct {
	path     string
	dek      []byte // Datenschlüssel, mit dem Data verschlüsselt ist
	slots    []Slot
	ad       *ADConfig
	user     string
	slotUser string // Slot, mit dem geöffnet wurde (bei AD-Benutzern der Gruppen-Slot)
	priv     *ecdh.PrivateKey
	kek      []byte // aus dem Passwort abgeleitet; nil, wenn das Passwort anderswo geändert wurde
	mfa      *MFA
	lastHash [32]byte // Hash der Datei, wie wir sie zuletzt gelesen oder geschrieben haben
	Data     Data
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

func newSlot(user, password string, keyFile []byte, mustChange bool) (Slot, *ecdh.PrivateKey, []byte, error) {
	kdf, err := defaultKDF()
	if err != nil {
		return Slot{}, nil, nil, err
	}
	kek, err := deriveKey(password, keyFile, kdf)
	if err != nil {
		return Slot{}, nil, nil, err
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Slot{}, nil, nil, err
	}
	pb, err := sealBox(kek, priv.Bytes(), aadPriv(user))
	if err != nil {
		return Slot{}, nil, nil, err
	}
	return Slot{
		User: user, KDF: kdf, KeyFile: len(keyFile) > 0, Pub: priv.PublicKey().Bytes(), Priv: pb,
		MustChange: mustChange, ChangedAt: time.Now().UTC(),
	}, priv, kek, nil
}

func setSlotMFA(s *Slot, kek []byte, m *MFA) error {
	if m == nil {
		s.MFA = nil
		return nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	box, err := sealBox(kek, b, aadMFA(s.User))
	clear(b)
	if err != nil {
		return err
	}
	s.MFA = &box
	return nil
}

// Create legt einen neuen Tresor mit einem ersten Benutzer (Admin) an und speichert ihn sofort.
func Create(path, user, password string, keyFile []byte, mfa MFA) (*Vault, error) {
	if Exists(path) {
		return nil, errors.New("an diesem Ort existiert bereits ein Tresor")
	}
	user = strings.TrimSpace(user)
	if user == "" {
		return nil, errors.New("Benutzername fehlt")
	}
	slot, priv, kek, err := newSlot(user, password, keyFile, false)
	if err != nil {
		return nil, err
	}
	if err := setSlotMFA(&slot, kek, &mfa); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	v := &Vault{
		path: path, dek: randomKey(), slots: []Slot{slot}, user: user, slotUser: user, priv: priv, kek: kek, mfa: &mfa,
		Data: Data{
			Folders:  []Folder{{ID: NewID(), Name: "Allgemein", Updated: now}},
			Entries:  []Entry{},
			Users:    []UserInfo{{Name: user, Role: RoleAdmin, Created: now, ChangedAt: now}},
			Settings: Settings{AutoLockMinutes: 5, ClipboardSeconds: 20},
		},
	}
	return v, v.write()
}

// Open entschlüsselt einen vorhandenen Tresor für einen Benutzer. Ist user leer und hat der
// Tresor nur einen Benutzer, wird dieser genommen. Die MFA-Daten des Benutzers werden mitgeliefert
// (nil, wenn er noch keine eingerichtet hat). Tresore im Format 1 werden dabei übernommen.
func Open(path, user, password string, keyFile []byte) (*Vault, *MFA, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	ver, h, f, err := parse(raw)
	if err != nil {
		return nil, nil, err
	}
	if ver == 1 {
		return migrateV1(path, raw, user, password, keyFile)
	}
	i := slotFor(h.Users, user)
	if i < 0 {
		return nil, nil, ErrBadCredentials
	}
	slot := h.Users[i]
	if slot.KeyFile && len(keyFile) == 0 {
		return nil, nil, ErrBadCredentials
	}
	if !slot.KeyFile {
		keyFile = nil
	}
	kek, err := deriveKey(password, keyFile, slot.KDF)
	if err != nil {
		return nil, nil, err
	}
	pb, err := openBox(kek, slot.Priv, aadPriv(slot.User))
	if err != nil {
		return nil, nil, ErrBadCredentials
	}
	priv, err := ecdh.X25519().NewPrivateKey(pb)
	clear(pb)
	if err != nil {
		return nil, nil, ErrBadCredentials
	}
	dek, err := openSealed(priv, slot.DEK, aadDEK(slot.User))
	if err != nil {
		return nil, nil, ErrBadCredentials
	}
	v := &Vault{path: path, dek: dek, slots: h.Users, ad: h.AD, user: slot.User, slotUser: slot.User, priv: priv, kek: kek, lastHash: sha256.Sum256(raw)}
	if err := v.decryptData(f); err != nil {
		return nil, nil, err
	}
	if slot.MFA != nil {
		mb, err := openBox(kek, *slot.MFA, aadMFA(slot.User))
		if err != nil {
			return nil, nil, ErrBadCredentials
		}
		var m MFA
		err = json.Unmarshal(mb, &m)
		clear(mb)
		if err != nil {
			return nil, nil, errors.New("MFA-Daten sind beschädigt")
		}
		v.mfa = &m
	}
	return v, v.MFA(), nil
}

func (v *Vault) decryptData(f file) error {
	pt, err := openBox(v.dek, f.Data, f.Header)
	if err != nil {
		return ErrBadCredentials
	}
	var d Data
	err = json.Unmarshal(pt, &d)
	clear(pt)
	if err != nil {
		return errors.New("Tresorinhalt ist beschädigt")
	}
	if d.Settings.AutoLockMinutes == 0 {
		d.Settings.AutoLockMinutes = 5
	}
	if d.Settings.ClipboardSeconds == 0 {
		d.Settings.ClipboardSeconds = 20
	}
	if d.Entries == nil {
		d.Entries = []Entry{}
	}
	v.Data = d
	return nil
}

// migrateV1 übernimmt einen Tresor aus Format 1. Der bisherige Zugang wird zum ersten Admin.
func migrateV1(path string, raw []byte, user, password string, keyFile []byte) (*Vault, *MFA, error) {
	d, err := openV1(raw, password, keyFile)
	if err != nil {
		return nil, nil, err
	}
	user = strings.TrimSpace(user)
	if user == "" {
		user = "admin"
	}
	var hv headerV1
	var ff fileV1
	json.Unmarshal(raw, &ff)
	json.Unmarshal([]byte(ff.Header), &hv)
	if !hv.KeyFileNeeded {
		keyFile = nil
	}
	slot, priv, kek, err := newSlot(user, password, keyFile, false)
	if err != nil {
		return nil, nil, err
	}
	mfa := d.LegacyMFA
	if mfa == nil {
		mfa = &MFA{}
	}
	if err := setSlotMFA(&slot, kek, mfa); err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC()
	d.LegacyMFA = nil
	d.Users = []UserInfo{{Name: user, Role: RoleAdmin, Created: now, ChangedAt: now}}
	v := &Vault{path: path, dek: randomKey(), slots: []Slot{slot}, user: user, priv: priv, kek: kek, mfa: mfa, Data: d}
	if err := os.WriteFile(path+".v1.bak", raw, 0o600); err != nil {
		return nil, nil, fmt.Errorf("Sicherung des alten Tresors fehlgeschlagen: %w", err)
	}
	v.lastHash = sha256.Sum256(raw)
	if err := v.write(); err != nil {
		return nil, nil, err
	}
	return v, v.MFA(), nil
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
	for i := range v.slots {
		s, err := sealTo(v.slots[i].Pub, v.dek, aadDEK(v.slots[i].User))
		if err != nil {
			return err
		}
		v.slots[i].DEK = s
	}
	hb, err := json.Marshal(header{Version: formatVersion, Cipher: "aes-256-gcm", Users: v.slots, AD: v.ad})
	if err != nil {
		return err
	}
	pt, err := json.Marshal(v.Data)
	if err != nil {
		return err
	}
	box, err := sealBox(v.dek, pt, string(hb))
	clear(pt)
	if err != nil {
		return err
	}
	out, err := json.MarshalIndent(file{Header: string(hb), Data: box}, "", "  ")
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
	// Die Schlüsseldatei der AD-Gruppe gehört zum Tresor und zieht mit um.
	if key, err := os.ReadFile(ADKeyPath(old)); err == nil {
		if err := os.WriteFile(ADKeyPath(path), key, 0o600); err != nil {
			return fmt.Errorf("Tresor verschoben, aber die AD-Schlüsseldatei konnte nicht kopiert werden: %w", err)
		}
	}
	return nil
}

// User liefert den angemeldeten Benutzer.
func (v *Vault) User() string { return v.user }

// Role liefert die Rolle des angemeldeten Benutzers.
func (v *Vault) Role() string {
	if v.IsADUser() {
		if v.ad != nil && v.ad.Role == RoleAdmin {
			return RoleAdmin
		}
		return RoleUser
	}
	for _, u := range v.Data.Users {
		if strings.EqualFold(u.Name, v.user) {
			return u.Role
		}
	}
	return RoleUser
}

// IsAdmin meldet, ob der angemeldete Benutzer Benutzer verwalten darf.
func (v *Vault) IsAdmin() bool { return v.Role() == RoleAdmin }

func (v *Vault) ownSlot() *Slot {
	if i := findSlot(v.slots, v.slotName()); i >= 0 {
		return &v.slots[i]
	}
	return nil
}

// MustChange meldet, ob der Benutzer noch mit einem Startpasswort angemeldet ist.
func (v *Vault) MustChange() bool {
	s := v.ownSlot()
	return s != nil && s.MustChange
}

// MFA liefert eine Kopie der MFA-Daten des angemeldeten Benutzers (nil = nicht eingerichtet).
func (v *Vault) MFA() *MFA {
	if v.mfa == nil || v.mfa.TOTPSecret == "" {
		return nil
	}
	m := *v.mfa
	m.RecoveryCodes = append([]string{}, v.mfa.RecoveryCodes...)
	return &m
}

var errReLogin = errors.New("Dein Passwort wurde auf einem anderen Gerät geändert. Bitte sperren und neu anmelden.")

// SetMFA speichert neue MFA-Daten für den angemeldeten Benutzer.
func (v *Vault) SetMFA(m MFA) error {
	if _, err := v.Refresh(); err != nil {
		return err
	}
	if v.IsADUser() {
		return v.setADMFA(m)
	}
	s := v.ownSlot()
	if s == nil || v.kek == nil {
		return errReLogin
	}
	m.ChangedAt = time.Now().UTC()
	old := *s
	if err := setSlotMFA(s, v.kek, &m); err != nil {
		return err
	}
	s.ChangedAt = m.ChangedAt
	if err := v.write(); err != nil {
		*s = old
		return err
	}
	v.mfa = &m
	return nil
}

// ChangeCredentials setzt für den angemeldeten Benutzer ein neues Passwort und/oder eine neue
// Schlüsseldatei (nil = keine).
func (v *Vault) ChangeCredentials(password string, keyFile []byte) error {
	if v.IsADUser() {
		return errors.New("Dein Passwort ist dein AD-Passwort und wird im Active Directory geändert")
	}
	if _, err := v.Refresh(); err != nil {
		return err
	}
	s := v.ownSlot()
	if s == nil {
		return ErrUserRemoved
	}
	kdf, err := defaultKDF()
	if err != nil {
		return err
	}
	kek, err := deriveKey(password, keyFile, kdf)
	if err != nil {
		return err
	}
	old := *s
	pb, err := sealBox(kek, v.priv.Bytes(), aadPriv(s.User))
	if err != nil {
		return err
	}
	s.KDF, s.KeyFile, s.Priv, s.MustChange, s.ChangedAt = kdf, len(keyFile) > 0, pb, false, time.Now().UTC()
	if err := setSlotMFA(s, kek, v.mfa); err != nil {
		*s = old
		return err
	}
	if err := v.write(); err != nil {
		*s = old
		return err
	}
	v.kek = kek
	return nil
}

// KeyFileNeeded meldet, ob der angemeldete Benutzer eine Schlüsseldatei verwendet.
func (v *Vault) KeyFileNeeded() bool {
	s := v.ownSlot()
	return s != nil && s.KeyFile
}

// Close entfernt die Schlüssel aus dem Speicher.
func (v *Vault) Close() {
	clear(v.dek)
	clear(v.kek)
	v.dek, v.kek, v.priv, v.mfa = nil, nil, nil, nil
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
		e.Updated, e.UpdatedBy = now, v.user
		*old = e
		return e
	}
	e.ID = NewID()
	e.Created, e.Updated, e.UpdatedBy = now, now, v.user
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
