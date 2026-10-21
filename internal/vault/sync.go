package vault

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"time"
)

// ErrChangedElsewhere bedeutet, dass auf einem anderen Gerät Master-Passwort oder
// Schlüsseldatei geändert wurden. Der Tresor muss dann neu entsperrt werden.
var ErrChangedElsewhere = errors.New("Master-Passwort oder Schlüsseldatei wurden auf einem anderen Gerät geändert. Bitte neu entsperren.")

const tombstoneTTL = 180 * 24 * time.Hour

// Refresh prüft, ob die Datei seit dem letzten Lesen/Schreiben von einem anderen Gerät
// geändert wurde, und führt diese Änderungen mit dem Stand im Speicher zusammen.
func (v *Vault) Refresh() (changed bool, err error) {
	raw, err := os.ReadFile(v.path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil // z. B. beim ersten Speichern oder nach Verschieben
	}
	if err != nil {
		return false, err
	}
	hash := sha256.Sum256(raw)
	if hash == v.lastHash {
		return false, nil
	}
	h, ff, err := readHeader(raw)
	if err != nil {
		return false, err
	}
	if h.KeyFileNeeded != v.keyFileNeeded || !bytes.Equal(h.KDF.Salt, v.kdf.Salt) {
		return false, ErrChangedElsewhere
	}
	pt, err := decrypt(v.key, h, ff)
	if err != nil {
		return false, ErrChangedElsewhere
	}
	var remote Data
	err = json.Unmarshal(pt, &remote)
	clear(pt)
	if err != nil {
		return false, errors.New("Tresorinhalt auf dem Speicherort ist beschädigt")
	}
	v.Data = Merge(v.Data, remote)
	v.lastHash = hash
	return true, nil
}

// Merge führt zwei Fassungen eines Tresors zusammen. Pro Eintrag und Ordner gewinnt
// die neuere Änderung; Löschungen gewinnen gegen ältere Änderungen.
func Merge(local, remote Data) Data {
	now := time.Now().UTC()
	tomb := map[string]time.Time{}
	for _, t := range append(append([]Tombstone{}, local.Deleted...), remote.Deleted...) {
		if now.Sub(t.At) > tombstoneTTL {
			continue
		}
		if t.At.After(tomb[t.ID]) {
			tomb[t.ID] = t.At
		}
	}
	alive := func(id string, updated time.Time) bool {
		t, ok := tomb[id]
		return !ok || updated.After(t)
	}

	out := Data{MFA: local.MFA, Settings: local.Settings}
	if remote.MFA.ChangedAt.After(local.MFA.ChangedAt) {
		out.MFA = remote.MFA
	}
	if remote.Settings.ChangedAt.After(local.Settings.ChangedAt) {
		out.Settings = remote.Settings
	}

	// Ordner
	rf := map[string]Folder{}
	for _, f := range remote.Folders {
		rf[f.ID] = f
	}
	seen := map[string]bool{}
	for _, f := range local.Folders {
		if r, ok := rf[f.ID]; ok && r.Updated.After(f.Updated) {
			f = r
		}
		seen[f.ID] = true
		if alive(f.ID, f.Updated) {
			out.Folders = append(out.Folders, f)
		}
	}
	for _, f := range remote.Folders {
		if !seen[f.ID] && alive(f.ID, f.Updated) {
			out.Folders = append(out.Folders, f)
		}
	}
	exists := map[string]bool{}
	for _, f := range out.Folders {
		exists[f.ID] = true
	}
	for i := range out.Folders {
		if !exists[out.Folders[i].ParentID] {
			out.Folders[i].ParentID = ""
		}
	}

	// Einträge
	re := map[string]Entry{}
	for _, e := range remote.Entries {
		re[e.ID] = e
	}
	seen = map[string]bool{}
	for _, e := range local.Entries {
		if r, ok := re[e.ID]; ok && r.Updated.After(e.Updated) {
			e = r
		}
		seen[e.ID] = true
		if alive(e.ID, e.Updated) {
			out.Entries = append(out.Entries, e)
		}
	}
	for _, e := range remote.Entries {
		if !seen[e.ID] && alive(e.ID, e.Updated) {
			out.Entries = append(out.Entries, e)
		}
	}
	if out.Entries == nil {
		out.Entries = []Entry{}
	}
	for i := range out.Entries {
		if !exists[out.Entries[i].FolderID] {
			out.Entries[i].FolderID = ""
		}
	}

	for id, at := range tomb {
		out.Deleted = append(out.Deleted, Tombstone{ID: id, At: at})
	}
	slices.SortFunc(out.Deleted, func(a, b Tombstone) int { return strings.Compare(a.ID, b.ID) })
	return out
}

func (v *Vault) tombstone(id string) {
	v.Data.Deleted = append(v.Data.Deleted, Tombstone{ID: id, At: time.Now().UTC()})
}
