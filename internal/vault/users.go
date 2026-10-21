package vault

import (
	"crypto/rand"
	"errors"
	"slices"
	"strings"
	"time"
)

// ErrUserRemoved bedeutet, dass der angemeldete Benutzer auf einem anderen Gerät entfernt wurde.
var ErrUserRemoved = errors.New("Dein Benutzer wurde aus diesem Tresor entfernt.")

var errNotAdmin = errors.New("Nur Admins dürfen Benutzer verwalten")

// UserView ist ein Benutzer, wie ihn die Benutzerverwaltung anzeigt.
type UserView struct {
	Name       string    `json:"name"`
	Role       string    `json:"role"`
	MFA        bool      `json:"mfa"`
	MustChange bool      `json:"mustChange"`
	KeyFile    bool      `json:"keyFile"`
	AD         bool      `json:"ad"`
	Created    time.Time `json:"created"`
}

// Users listet alle Benutzer des Tresors.
func (v *Vault) Users() []UserView {
	out := []UserView{}
	for _, s := range v.slots {
		if s.Group {
			continue
		}
		u := UserView{Name: s.User, Role: RoleUser, MFA: s.MFA != nil, MustChange: s.MustChange, KeyFile: s.KeyFile}
		for _, info := range v.Data.Users {
			if strings.EqualFold(info.Name, s.User) {
				u.Role, u.Created = info.Role, info.Created
			}
		}
		out = append(out, u)
	}
	for _, info := range v.Data.Users {
		if info.AD {
			role := RoleUser
			if v.ad != nil && v.ad.Role == RoleAdmin {
				role = RoleAdmin
			}
			out = append(out, UserView{Name: info.Name, Role: role, MFA: info.MFA != nil, AD: true, Created: info.Created})
		}
	}
	slices.SortFunc(out, func(a, b UserView) int { return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)) })
	return out
}

// StartPassword erzeugt ein gut abtippbares Startpasswort.
func StartPassword() string {
	const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 16)
	rand.Read(b)
	var sb strings.Builder
	for i, x := range b {
		if i > 0 && i%4 == 0 {
			sb.WriteByte('-')
		}
		sb.WriteByte(alphabet[int(x)%len(alphabet)])
	}
	return sb.String()
}

func validRole(r string) bool { return r == RoleAdmin || r == RoleUser }

func userTomb(name string) string { return "user:" + strings.ToLower(name) }

// AddUser legt einen Benutzer mit Startpasswort an. Beim ersten Anmelden muss er ein eigenes
// Passwort setzen und seine Authenticator-App einrichten.
func (v *Vault) AddUser(name, role string) (string, error) {
	if !v.IsAdmin() {
		return "", errNotAdmin
	}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 || strings.ContainsAny(name, ":/\\") {
		return "", errors.New("Ungültiger Benutzername")
	}
	if !validRole(role) {
		return "", errors.New("Ungültige Rolle")
	}
	if _, err := v.Refresh(); err != nil {
		return "", err
	}
	if findSlot(v.slots, name) >= 0 || v.adUser(name) != nil {
		return "", errors.New("Diesen Benutzer gibt es schon")
	}
	pw := StartPassword()
	slot, _, _, err := newSlot(name, pw, nil, true)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	v.slots = append(v.slots, slot)
	v.Data.Users = slices.DeleteFunc(v.Data.Users, func(u UserInfo) bool { return strings.EqualFold(u.Name, name) })
	v.Data.Users = append(v.Data.Users, UserInfo{Name: name, Role: role, Created: now, ChangedAt: now})
	v.Data.Deleted = slices.DeleteFunc(v.Data.Deleted, func(t Tombstone) bool { return t.ID == userTomb(name) })
	return pw, v.write()
}

// ResetUser vergibt einem Benutzer ein neues Startpasswort und setzt seine MFA zurück
// (z. B. Passwort vergessen oder Handy verloren).
func (v *Vault) ResetUser(name string) (string, error) {
	if !v.IsAdmin() {
		return "", errNotAdmin
	}
	if _, err := v.Refresh(); err != nil {
		return "", err
	}
	if u := v.adUser(name); u != nil {
		// AD-Benutzer: Passwort kommt aus dem AD, nur die MFA wird zurückgesetzt.
		if strings.EqualFold(u.Name, v.user) {
			return "", errors.New("Das eigene Konto bitte über die Einstellungen ändern")
		}
		u.MFA, u.ChangedAt = nil, time.Now().UTC()
		return "", v.write()
	}
	i := findSlot(v.slots, name)
	if i < 0 || v.slots[i].Group {
		return "", errors.New("Benutzer nicht gefunden")
	}
	if strings.EqualFold(v.slots[i].User, v.user) {
		return "", errors.New("Das eigene Konto bitte über die Einstellungen ändern")
	}
	pw := StartPassword()
	slot, _, _, err := newSlot(v.slots[i].User, pw, nil, true)
	if err != nil {
		return "", err
	}
	v.slots[i] = slot
	// Neuer Schlüssel für die Daten, damit das alte Schlüsselpaar nichts mehr öffnet.
	v.dek = randomKey()
	return pw, v.write()
}

// RemoveUser entfernt einen Benutzer und verschlüsselt den Tresor mit einem neuen Datenschlüssel.
func (v *Vault) RemoveUser(name string) error {
	if !v.IsAdmin() {
		return errNotAdmin
	}
	if _, err := v.Refresh(); err != nil {
		return err
	}
	if u := v.adUser(name); u != nil {
		// AD-Benutzer: Zugang steuert die AD-Gruppe. Entfernen löscht seine MFA und die Angaben;
		// solange er in der Gruppe ist, kann er sich neu anmelden und die MFA neu einrichten.
		if strings.EqualFold(u.Name, v.user) {
			return errors.New("Du kannst dich nicht selbst entfernen")
		}
		n := u.Name
		v.Data.Users = slices.DeleteFunc(v.Data.Users, func(x UserInfo) bool { return x.AD && strings.EqualFold(x.Name, n) })
		v.Data.Deleted = append(v.Data.Deleted, Tombstone{ID: userTomb(n), At: time.Now().UTC()})
		return v.write()
	}
	i := findSlot(v.slots, name)
	if i < 0 || v.slots[i].Group {
		return errors.New("Benutzer nicht gefunden")
	}
	if strings.EqualFold(v.slots[i].User, v.user) {
		return errors.New("Du kannst dich nicht selbst entfernen")
	}
	name = v.slots[i].User
	if v.roleOf(name) == RoleAdmin && v.adminCount() <= 1 {
		return errors.New("Der letzte Admin kann nicht entfernt werden")
	}
	v.slots = slices.Delete(v.slots, i, i+1)
	v.Data.Users = slices.DeleteFunc(v.Data.Users, func(u UserInfo) bool { return strings.EqualFold(u.Name, name) })
	v.Data.Deleted = append(v.Data.Deleted, Tombstone{ID: userTomb(name), At: time.Now().UTC()})
	v.dek = randomKey()
	return v.write()
}

// SetRole ändert die Rolle eines Benutzers.
func (v *Vault) SetRole(name, role string) error {
	if !v.IsAdmin() {
		return errNotAdmin
	}
	if !validRole(role) {
		return errors.New("Ungültige Rolle")
	}
	if _, err := v.Refresh(); err != nil {
		return err
	}
	if v.adUser(name) != nil {
		return errors.New("Die Rolle der AD-Benutzer wird in den AD-Einstellungen festgelegt")
	}
	if role != RoleAdmin && v.roleOf(name) == RoleAdmin && v.adminCount() <= 1 {
		return errors.New("Es muss mindestens einen Admin geben")
	}
	for i := range v.Data.Users {
		if strings.EqualFold(v.Data.Users[i].Name, name) {
			v.Data.Users[i].Role = role
			v.Data.Users[i].ChangedAt = time.Now().UTC()
			return v.write()
		}
	}
	return errors.New("Benutzer nicht gefunden")
}

func (v *Vault) roleOf(name string) string {
	for _, u := range v.Data.Users {
		if strings.EqualFold(u.Name, name) {
			return u.Role
		}
	}
	return RoleUser
}

func (v *Vault) adminCount() int {
	n := 0
	for _, s := range v.slots {
		if v.roleOf(s.User) == RoleAdmin {
			n++
		}
	}
	return n
}
