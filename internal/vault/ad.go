package vault

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"
)

// ADConfig beschreibt die Anmeldung über Active Directory. Sie steht unverschlüsselt im Kopf,
// weil sie vor dem Entschlüsseln gebraucht wird; sie enthält keine Geheimnisse.
//
// Mitglieder der Gruppe öffnen den Tresor über einen gemeinsamen Gruppen-Slot. Dessen Schlüssel
// liegt in der Datei <tresor>.adkey, die per NTFS-Rechten nur für die Gruppe lesbar sein soll.
// PassMind lässt nur hinein, wer sich per LDAP mit seinem AD-Passwort anmeldet, in der Gruppe ist
// und den Code seiner eigenen Authenticator-App eingibt.
type ADConfig struct {
	Server     string    `json:"server"`               // z. B. dc01.firma.local oder ldaps://dc01:636
	Domain     string    `json:"domain"`               // z. B. firma.local (für user@domain)
	BaseDN     string    `json:"baseDN,omitempty"`     // leer = aus der Domäne abgeleitet
	Group      string    `json:"group"`                // Gruppenname (z. B. GR-PASS-ADM) oder DN
	Role       string    `json:"role"`                 // Rolle der AD-Benutzer in PassMind
	SkipVerify bool      `json:"skipVerify,omitempty"` // Zertifikat des DC nicht prüfen
	ChangedAt  time.Time `json:"changedAt"`
}

// Enabled meldet, ob die AD-Anmeldung vollständig eingerichtet ist.
func (c *ADConfig) Enabled() bool {
	return c != nil && c.Server != "" && c.Domain != "" && c.Group != ""
}

// ErrADKey bedeutet, dass die Schlüsseldatei der AD-Gruppe nicht gelesen werden kann.
var ErrADKey = errors.New("Die AD-Schlüsseldatei neben dem Tresor kann nicht gelesen werden. Bist du in der richtigen Gruppe und hat die Datei die passenden Freigaberechte?")

const groupSlotName = "@ad-gruppe"

// ADKeyPath ist der Ort der Schlüsseldatei der AD-Gruppe.
func ADKeyPath(vaultPath string) string { return vaultPath + ".adkey" }

// ReadADConfig liest die AD-Einstellungen aus dem Kopf, ohne zu entschlüsseln.
func ReadADConfig(path string) *ADConfig {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	ver, h, _, err := parse(raw)
	if err != nil || ver != formatVersion || !h.AD.Enabled() {
		return nil
	}
	return h.AD
}

func (v *Vault) slotName() string {
	if v.slotUser != "" {
		return v.slotUser
	}
	return v.user
}

// IsADUser meldet, ob der angemeldete Benutzer über Active Directory angemeldet ist.
func (v *Vault) IsADUser() bool { return v.slotName() == groupSlotName }

// ADConfig liefert die AD-Einstellungen des geöffneten Tresors (nil = keine).
func (v *Vault) ADConfig() *ADConfig {
	if !v.ad.Enabled() {
		return nil
	}
	c := *v.ad
	return &c
}

// EnableAD speichert die AD-Einstellungen. Beim ersten Einschalten wird der Gruppen-Slot
// angelegt und seine Schlüsseldatei neben den Tresor geschrieben.
func (v *Vault) EnableAD(c ADConfig) error {
	if !v.IsAdmin() || v.IsADUser() {
		return errors.New("Nur ein lokaler Admin darf die AD-Anmeldung einrichten")
	}
	c.Server, c.Domain, c.Group, c.BaseDN = strings.TrimSpace(c.Server), strings.TrimSpace(c.Domain), strings.TrimSpace(c.Group), strings.TrimSpace(c.BaseDN)
	if !c.Enabled() {
		return errors.New("Bitte Server, Domäne und Gruppe angeben")
	}
	if c.Role == "" {
		c.Role = RoleUser
	}
	if !validRole(c.Role) {
		return errors.New("Ungültige Rolle")
	}
	if _, err := v.Refresh(); err != nil {
		return err
	}
	oldAD, oldSlots := v.ad, v.slots
	c.ChangedAt = time.Now().UTC()
	v.ad = &c
	if findSlot(v.slots, groupSlotName) < 0 || !Exists(ADKeyPath(v.path)) {
		kek := randomKey()
		priv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		pb, err := sealBox(kek, priv.Bytes(), aadPriv(groupSlotName))
		if err != nil {
			return err
		}
		v.slots = slices.DeleteFunc(slices.Clone(v.slots), func(s Slot) bool { return s.User == groupSlotName })
		v.slots = append(v.slots, Slot{User: groupSlotName, Group: true, Pub: priv.PublicKey().Bytes(), Priv: pb, ChangedAt: c.ChangedAt})
		if err := writeADKey(v.path, kek); err != nil {
			v.ad, v.slots = oldAD, oldSlots
			return fmt.Errorf("AD-Schlüsseldatei konnte nicht geschrieben werden: %w", err)
		}
	}
	if err := v.write(); err != nil {
		v.ad, v.slots = oldAD, oldSlots
		return err
	}
	return nil
}

// DisableAD schaltet die AD-Anmeldung aus. Der Gruppen-Slot wird entfernt und der Tresor mit
// einem neuen Datenschlüssel verschlüsselt, die alte Schlüsseldatei taugt danach nichts mehr.
func (v *Vault) DisableAD() error {
	if !v.IsAdmin() || v.IsADUser() {
		return errors.New("Nur ein lokaler Admin darf die AD-Anmeldung ausschalten")
	}
	if _, err := v.Refresh(); err != nil {
		return err
	}
	now := time.Now().UTC()
	v.ad = &ADConfig{ChangedAt: now} // leer = aus; mit Zeitstempel, damit das Zusammenführen es übernimmt
	v.slots = slices.DeleteFunc(v.slots, func(s Slot) bool { return s.User == groupSlotName })
	v.Data.Deleted = append(v.Data.Deleted, Tombstone{ID: userTomb(groupSlotName), At: now})
	v.dek = randomKey()
	if err := v.write(); err != nil {
		return err
	}
	os.Remove(ADKeyPath(v.path))
	return nil
}

func writeADKey(vaultPath string, kek []byte) error {
	content := "PassMind AD-Gruppenschlüssel. Nur für die AD-Gruppe lesbar machen (NTFS-Rechte)!\n" + base64.StdEncoding.EncodeToString(kek) + "\n"
	return os.WriteFile(ADKeyPath(vaultPath), []byte(content), 0o600)
}

func readADKey(vaultPath string) ([]byte, error) {
	raw, err := os.ReadFile(ADKeyPath(vaultPath))
	if err != nil {
		return nil, ErrADKey
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	kek, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[len(lines)-1]))
	if err != nil || len(kek) != 32 {
		return nil, errors.New("Die AD-Schlüsseldatei ist beschädigt")
	}
	return kek, nil
}

// OpenAD öffnet den Tresor für einen AD-Benutzer über den Gruppen-Slot. Der Aufrufer muss
// vorher per LDAP geprüft haben, dass Passwort und Gruppenmitgliedschaft stimmen. Geliefert
// wird die MFA des Benutzers (nil = noch nicht eingerichtet).
func OpenAD(path, user string) (*Vault, *MFA, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	ver, h, f, err := parse(raw)
	if err != nil {
		return nil, nil, err
	}
	if ver != formatVersion || !h.AD.Enabled() {
		return nil, nil, errors.New("Die AD-Anmeldung ist für diesen Tresor nicht eingerichtet")
	}
	i := findSlot(h.Users, groupSlotName)
	if i < 0 {
		return nil, nil, errors.New("Die AD-Anmeldung ist für diesen Tresor nicht eingerichtet")
	}
	kek, err := readADKey(path)
	if err != nil {
		return nil, nil, err
	}
	defer clear(kek)
	pb, err := openBox(kek, h.Users[i].Priv, aadPriv(groupSlotName))
	if err != nil {
		return nil, nil, errors.New("Die AD-Schlüsseldatei passt nicht zu diesem Tresor")
	}
	priv, err := ecdh.X25519().NewPrivateKey(pb)
	clear(pb)
	if err != nil {
		return nil, nil, ErrBadCredentials
	}
	dek, err := openSealed(priv, h.Users[i].DEK, aadDEK(groupSlotName))
	if err != nil {
		return nil, nil, errors.New("Die AD-Schlüsseldatei passt nicht zu diesem Tresor")
	}
	v := &Vault{path: path, dek: dek, slots: h.Users, ad: h.AD, user: user, slotUser: groupSlotName, priv: priv, lastHash: sha256.Sum256(raw)}
	if err := v.decryptData(f); err != nil {
		return nil, nil, err
	}
	if u := v.adUser(user); u != nil {
		v.user = u.Name
		if u.MFA != nil {
			m := *u.MFA
			v.mfa = &m
		}
	}
	return v, v.MFA(), nil
}

func (v *Vault) adUser(name string) *UserInfo {
	for i := range v.Data.Users {
		if v.Data.Users[i].AD && strings.EqualFold(v.Data.Users[i].Name, name) {
			return &v.Data.Users[i]
		}
	}
	return nil
}

// setADMFA speichert die MFA eines AD-Benutzers im verschlüsselten Datenteil.
func (v *Vault) setADMFA(m MFA) error {
	m.ChangedAt = time.Now().UTC()
	u := v.adUser(v.user)
	if u == nil {
		v.Data.Users = append(v.Data.Users, UserInfo{Name: v.user, Role: v.Role(), AD: true, Created: m.ChangedAt})
		u = &v.Data.Users[len(v.Data.Users)-1]
	}
	mc := m
	u.MFA, u.ChangedAt = &mc, m.ChangedAt
	v.Data.Deleted = slices.DeleteFunc(v.Data.Deleted, func(t Tombstone) bool { return t.ID == userTomb(v.user) })
	if err := v.write(); err != nil {
		return err
	}
	v.mfa = &m
	return nil
}
