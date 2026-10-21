package vault

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"slices"
	"strings"
	"time"
)

// ErrChangedElsewhere bedeutet, dass die Datei auf einem anderen Gerät so geändert wurde,
// dass sie mit den Schlüsseln dieser Sitzung nicht mehr lesbar ist.
var ErrChangedElsewhere = errors.New("Der Tresor wurde auf einem anderen Gerät neu verschlüsselt. Bitte neu anmelden.")

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
	ver, h, f, err := parse(raw)
	if err != nil {
		return false, err
	}
	if ver != formatVersion {
		return false, errors.New("Auf dem Speicherort liegt ein Tresor im alten Format. Bitte alle Rechner auf die neue PassMind-Version aktualisieren.")
	}
	// Datenschlüssel: entweder unverändert, oder (nach Entfernen eines Benutzers) neu und an uns versiegelt.
	remote := &Vault{dek: v.dek}
	if err := remote.decryptData(f); err != nil {
		i := findSlot(h.Users, v.user)
		if i < 0 {
			return false, ErrUserRemoved
		}
		dek, err := openSealed(v.priv, h.Users[i].DEK, aadDEK(v.user))
		if err != nil {
			return false, ErrChangedElsewhere
		}
		remote.dek = dek
		if err := remote.decryptData(f); err != nil {
			return false, ErrChangedElsewhere
		}
		v.dek = dek
	}
	v.Data = Merge(v.Data, remote.Data)
	own := v.ownSlot()
	var ownBefore Slot
	if own != nil {
		ownBefore = *own
	}
	v.slots = mergeSlots(v.slots, h.Users, v.Data.Deleted)
	own = v.ownSlot()
	if own == nil {
		return false, ErrUserRemoved
	}
	if own.ChangedAt.After(ownBefore.ChangedAt) && !bytes.Equal(own.KDF.Salt, ownBefore.KDF.Salt) {
		v.kek = nil // Passwort wurde anderswo geändert
	}
	if !bytes.Equal(own.Pub, v.priv.PublicKey().Bytes()) {
		return false, ErrChangedElsewhere // Zugang wurde vom Admin zurückgesetzt
	}
	v.lastHash = hash
	return true, nil
}

func mergeSlots(local, remote []Slot, deleted []Tombstone) []Slot {
	tomb := map[string]time.Time{}
	for _, t := range deleted {
		tomb[t.ID] = t.At
	}
	out := []Slot{}
	seen := map[string]bool{}
	add := func(s Slot) {
		if t, ok := tomb[userTomb(s.User)]; ok && !s.ChangedAt.After(t) {
			return
		}
		out = append(out, s)
	}
	for _, s := range local {
		if i := findSlot(remote, s.User); i >= 0 && remote[i].ChangedAt.After(s.ChangedAt) {
			s = remote[i]
		}
		seen[strings.ToLower(s.User)] = true
		add(s)
	}
	for _, s := range remote {
		if !seen[strings.ToLower(s.User)] {
			add(s)
		}
	}
	return out
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

	out := Data{Settings: local.Settings}
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

	// Benutzer (Rollen)
	ru := map[string]UserInfo{}
	for _, u := range remote.Users {
		ru[strings.ToLower(u.Name)] = u
	}
	seen = map[string]bool{}
	for _, u := range local.Users {
		k := strings.ToLower(u.Name)
		if r, ok := ru[k]; ok && r.ChangedAt.After(u.ChangedAt) {
			u = r
		}
		seen[k] = true
		if alive(userTomb(u.Name), u.ChangedAt) {
			out.Users = append(out.Users, u)
		}
	}
	for _, u := range remote.Users {
		if !seen[strings.ToLower(u.Name)] && alive(userTomb(u.Name), u.ChangedAt) {
			out.Users = append(out.Users, u)
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
