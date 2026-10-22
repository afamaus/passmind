package vault

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"
)

// Personal ist der persönliche Tresor eines Benutzers: eigene Ordner und Einträge, die kein
// anderer Benutzer lesen kann, auch kein Admin. Der Inhalt ist mit einem eigenen Schlüssel
// verschlüsselt. Bei lokalen Benutzern ist dieser an ihren öffentlichen Schlüssel versiegelt,
// bei AD-Benutzern (die sich einen Gruppen-Slot teilen) mit ihrem AD-Passwort verschlüsselt.
type Personal struct {
	User    string     `json:"user"`
	AD      bool       `json:"ad,omitempty"`
	Sealed  *SealedKey `json:"sealed,omitempty"` // lokal: an den öffentlichen Schlüssel des Benutzers
	KDF     *KDFParams `json:"kdf,omitempty"`    // AD: Ableitung aus dem AD-Passwort
	Wrapped *Box       `json:"wrapped,omitempty"`
	Data    Box        `json:"data"`
	Updated time.Time  `json:"updated"`
}

// PersonalState beschreibt den persönlichen Tresor des angemeldeten Benutzers.
type PersonalState struct {
	Available bool `json:"available"`
	Locked    bool `json:"locked"` // AD-Passwort wurde geändert, altes Passwort nötig
}

// ErrPersonalLocked bedeutet, dass der persönliche Tresor (noch) nicht geöffnet ist.
var ErrPersonalLocked = errors.New("Dein persönlicher Tresor ist gesperrt. Bitte zuerst mit deinem bisherigen AD-Passwort entsperren.")

func aadPKey(u string, ad bool) string  { return "pm-pkey:" + personalKey(u, ad) }
func aadPData(u string, ad bool) string { return "pm-pdata:" + personalKey(u, ad) }

func personalKey(u string, ad bool) string {
	if ad {
		return "ad:" + strings.ToLower(u)
	}
	return strings.ToLower(u)
}

func (d *Data) findPersonal(user string, ad bool) int {
	for i, p := range d.Personal {
		if p.AD == ad && strings.EqualFold(p.User, user) {
			return i
		}
	}
	return -1
}

func (d *Data) dropPersonal(user string, ad bool) {
	d.Personal = slices.DeleteFunc(d.Personal, func(p Personal) bool { return p.AD == ad && strings.EqualFold(p.User, user) })
}

// PersonalState liefert den Zustand des eigenen persönlichen Tresors.
func (v *Vault) PersonalState() PersonalState {
	return PersonalState{Available: v.personal != nil, Locked: v.plocked}
}

// PersonalData liefert den geöffneten persönlichen Tresor (nil = nicht geöffnet).
func (v *Vault) PersonalData() *Data { return v.personal }

// openPersonal öffnet den persönlichen Tresor des angemeldeten Benutzers oder legt (im Speicher)
// einen leeren an. adPassword wird nur für AD-Benutzer gebraucht.
func (v *Vault) openPersonal(adPassword string) error {
	ad := v.IsADUser()
	if ad && adPassword == "" {
		return nil // ohne Passwort bleibt der persönliche Tresor zu
	}
	fresh := func() error {
		if ad && (v.pkek == nil || v.pkdf == nil) {
			kdf, err := defaultKDF()
			if err != nil {
				return err
			}
			kek, err := deriveKey(adPassword, nil, kdf)
			if err != nil {
				return err
			}
			v.pkdf, v.pkek = &kdf, kek
		}
		v.personal, v.pkey, v.pdirty = &Data{Entries: []Entry{}}, randomKey(), true
		return nil
	}
	i := v.Data.findPersonal(v.user, ad)
	if i < 0 {
		return fresh()
	}
	p := v.Data.Personal[i]
	var key []byte
	var err error
	if ad {
		key, err = unwrapADKey(p, v.user, adPassword)
		if err != nil {
			// AD-Passwort wurde geändert: mit dem bisherigen entsperren lassen, dann neu verschlüsseln.
			kdf, err := defaultKDF()
			if err != nil {
				return err
			}
			kek, err := deriveKey(adPassword, nil, kdf)
			if err != nil {
				return err
			}
			v.pkdf, v.pkek, v.plocked = &kdf, kek, true
			return nil
		}
		kek, _ := deriveKey(adPassword, nil, *p.KDF)
		v.pkdf, v.pkek = p.KDF, kek
	} else if p.Sealed != nil {
		if key, err = openSealed(v.priv, *p.Sealed, aadPKey(v.user, false)); err != nil {
			// Neues Schlüsselpaar (vom Admin zurückgesetzt): der alte Inhalt ist nicht mehr lesbar.
			return fresh()
		}
	} else {
		return fresh()
	}
	d, err := decryptPersonal(p, key, v.user, ad)
	if err != nil {
		return err
	}
	v.personal, v.pkey = d, key
	return nil
}

func unwrapADKey(p Personal, user, password string) ([]byte, error) {
	if p.KDF == nil || p.Wrapped == nil {
		return nil, ErrBadCredentials
	}
	kek, err := deriveKey(password, nil, *p.KDF)
	if err != nil {
		return nil, err
	}
	defer clear(kek)
	return openBox(kek, *p.Wrapped, aadPKey(user, true))
}

func decryptPersonal(p Personal, key []byte, user string, ad bool) (*Data, error) {
	pt, err := openBox(key, p.Data, aadPData(user, ad))
	if err != nil {
		return nil, errors.New("Persönlicher Tresor ist beschädigt")
	}
	var d Data
	err = json.Unmarshal(pt, &d)
	clear(pt)
	if err != nil {
		return nil, errors.New("Persönlicher Tresor ist beschädigt")
	}
	if d.Entries == nil {
		d.Entries = []Entry{}
	}
	return &d, nil
}

// sealPersonal verschlüsselt einen geänderten persönlichen Tresor in die gemeinsamen Daten.
func (v *Vault) sealPersonal() error {
	if !v.pdirty || v.personal == nil || v.pkey == nil {
		return nil
	}
	ad := v.IsADUser()
	p := Personal{User: v.user, AD: ad, Updated: time.Now().UTC()}
	if ad {
		if v.pkek == nil || v.pkdf == nil {
			return ErrPersonalLocked
		}
		w, err := sealBox(v.pkek, v.pkey, aadPKey(v.user, true))
		if err != nil {
			return err
		}
		p.KDF, p.Wrapped = v.pkdf, &w
	} else {
		s := v.ownSlot()
		if s == nil {
			return ErrUserRemoved
		}
		sk, err := sealTo(s.Pub, v.pkey, aadPKey(v.user, false))
		if err != nil {
			return err
		}
		p.Sealed = &sk
	}
	plain := Data{Folders: v.personal.Folders, Entries: v.personal.Entries, Deleted: v.personal.Deleted}
	pt, err := json.Marshal(plain)
	if err != nil {
		return err
	}
	box, err := sealBox(v.pkey, pt, aadPData(v.user, ad))
	clear(pt)
	if err != nil {
		return err
	}
	p.Data = box
	if i := v.Data.findPersonal(v.user, ad); i >= 0 {
		v.Data.Personal[i] = p
	} else {
		v.Data.Personal = append(v.Data.Personal, p)
	}
	v.pdirty = false
	return nil
}

// mergeOwnPersonal übernimmt Änderungen am eigenen persönlichen Tresor, die auf einem anderen
// Gerät gemacht wurden (Eintrag für Eintrag, wie beim gemeinsamen Bereich).
func (v *Vault) mergeOwnPersonal(remote Data) {
	if v.personal == nil || v.pkey == nil {
		return
	}
	ad := v.IsADUser()
	ri := remote.findPersonal(v.user, ad)
	if ri < 0 {
		return
	}
	rp := remote.Personal[ri]
	if li := v.Data.findPersonal(v.user, ad); li >= 0 && !rp.Updated.After(v.Data.Personal[li].Updated) {
		return
	}
	rd, err := decryptPersonal(rp, v.pkey, v.user, ad)
	if err != nil {
		return // mit anderem Schlüssel angelegt (gleichzeitig auf zwei Geräten); unsere Fassung gewinnt
	}
	m := Merge(*v.personal, *rd)
	v.personal = &Data{Folders: m.Folders, Entries: m.Entries, Deleted: m.Deleted}
	v.pdirty = true
}

// UnlockPersonal öffnet den persönlichen Tresor eines AD-Benutzers nach einer Änderung seines
// AD-Passworts mit dem bisherigen Passwort und verschlüsselt ihn mit dem neuen.
func (v *Vault) UnlockPersonal(oldPassword string) error {
	if !v.plocked {
		return nil
	}
	ad := v.IsADUser()
	i := v.Data.findPersonal(v.user, ad)
	if i < 0 {
		return ErrBadCredentials
	}
	p := v.Data.Personal[i]
	key, err := unwrapADKey(p, v.user, oldPassword)
	if err != nil {
		return ErrBadCredentials
	}
	d, err := decryptPersonal(p, key, v.user, ad)
	if err != nil {
		return err
	}
	v.personal, v.pkey, v.plocked, v.pdirty = d, key, false, true
	return v.Save()
}

// ResetPersonal verwirft einen gesperrten persönlichen Tresor (bisheriges AD-Passwort vergessen)
// und legt einen leeren an.
func (v *Vault) ResetPersonal() error {
	if !v.plocked {
		return errors.New("Der persönliche Tresor ist nicht gesperrt")
	}
	v.personal, v.pkey, v.plocked, v.pdirty = &Data{Entries: []Entry{}}, randomKey(), false, true
	return v.Save()
}

func (v *Vault) space(personal bool) (*Data, error) {
	if !personal {
		return &v.Data, nil
	}
	if v.personal == nil {
		return nil, ErrPersonalLocked
	}
	return v.personal, nil
}

// SaveEntry legt einen Eintrag im gemeinsamen oder persönlichen Bereich an bzw. ändert ihn.
// Liegt der Eintrag bisher im anderen Bereich, wird er dorthin verschoben.
func (v *Vault) SaveEntry(e Entry, personal bool) (Entry, error) {
	dst, err := v.space(personal)
	if err != nil {
		return e, err
	}
	if e.FolderID != "" && !dst.folderExists(e.FolderID) {
		return e, errors.New("Ordner nicht gefunden")
	}
	if e.ID != "" {
		cur, inPersonal, ok := v.Lookup(e.ID)
		if !ok {
			e.ID = ""
		} else if inPersonal != personal {
			src, err := v.space(inPersonal)
			if err != nil {
				return e, err
			}
			src.deleteEntry(cur.ID)
			dst.Entries = append(dst.Entries, cur)
			dst.Deleted = slices.DeleteFunc(dst.Deleted, func(t Tombstone) bool { return t.ID == cur.ID })
			v.pdirty = true
		}
	}
	if personal {
		v.pdirty = true
	}
	return dst.upsertEntry(e, v.user), nil
}

// SaveFolder legt einen Ordner im gemeinsamen oder persönlichen Bereich an bzw. ändert ihn.
func (v *Vault) SaveFolder(f Folder, personal bool) (Folder, error) {
	dst, err := v.space(personal)
	if err != nil {
		return f, err
	}
	if f.ID != "" && !dst.folderExists(f.ID) {
		if other, _ := v.space(!personal); other != nil && other.folderExists(f.ID) {
			return f, errors.New("Ordner können nicht zwischen persönlichem und gemeinsamem Bereich verschoben werden. Verschiebe stattdessen die Einträge.")
		}
		f.ID = ""
	}
	if personal {
		v.pdirty = true
	}
	return dst.upsertFolder(f)
}

// ImportTarget liefert den Bereich, in den ein Import geht.
func (v *Vault) ImportTarget(personal bool) (*Data, error) {
	d, err := v.space(personal)
	if err == nil && personal {
		v.pdirty = true
	}
	return d, err
}

// AddImported legt einen importierten Eintrag in einem Bereich an.
func (v *Vault) AddImported(d *Data, e Entry, folderPath []string, folderID string) {
	if len(folderPath) > 0 {
		folderID = d.folderByPath(folderPath)
	}
	if folderID != "" && !d.folderExists(folderID) {
		folderID = ""
	}
	e.ID, e.FolderID = "", folderID
	d.upsertEntry(e, v.user)
}

// FolderPathIn liefert den Pfad eines Ordners im angegebenen Bereich.
func (d *Data) FolderPathIn(id string) []string { return d.folderPath(id) }

// FolderExists meldet, ob es den Ordner im angegebenen Bereich gibt.
func (v *Vault) FolderExists(id string, personal bool) bool {
	d, err := v.space(personal)
	return err == nil && d.folderExists(id)
}
