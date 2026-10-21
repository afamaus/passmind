// Package ldapauth prüft AD-Anmeldedaten und die Mitgliedschaft in einer Gruppe per LDAPS.
package ldapauth

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"passmind/internal/vault"
)

var (
	// ErrBadCredentials: Benutzer oder Passwort falsch (oder Konto gesperrt/deaktiviert).
	ErrBadCredentials = errors.New("AD-Benutzer oder Passwort ist falsch")
	// ErrNotInGroup: Anmeldung ok, aber nicht in der berechtigten Gruppe.
	ErrNotInGroup = errors.New("Dein AD-Konto ist nicht in der für PassMind berechtigten Gruppe")
)

// SplitUser zerlegt "anna", "FIRMA\anna" oder "anna@firma.local" in den Kontonamen und liefert
// den Namen, mit dem gebunden wird.
func SplitUser(input, domain string) (account, bindName string) {
	input = strings.TrimSpace(input)
	switch {
	case strings.Contains(input, `\`):
		account = input[strings.LastIndex(input, `\`)+1:]
		return account, input
	case strings.Contains(input, "@"):
		account, _, _ = strings.Cut(input, "@")
		return account, input
	default:
		return input, input + "@" + domain
	}
}

// BaseDN leitet aus der Domäne den Suchbereich ab, z. B. firma.local -> DC=firma,DC=local.
func BaseDN(c vault.ADConfig) string {
	if c.BaseDN != "" {
		return c.BaseDN
	}
	parts := strings.Split(strings.Trim(c.Domain, "."), ".")
	return "DC=" + strings.Join(parts, ",DC=")
}

func serverURL(server string) (string, string, error) {
	if !strings.Contains(server, "://") {
		server = "ldaps://" + server
	}
	u, err := url.Parse(server)
	if err != nil || u.Hostname() == "" {
		return "", "", fmt.Errorf("ungültige Serveradresse %q", server)
	}
	if u.Port() == "" {
		port := "636"
		if u.Scheme == "ldap" {
			port = "389"
		}
		u.Host = net.JoinHostPort(u.Hostname(), port)
	}
	return u.String(), u.Hostname(), nil
}

// cipherSuites erweitert die Standardauswahl um Verfahren, die ältere Domänencontroller
// (z. B. Windows Server 2012 R2 mit RSA-Zertifikat) für TLS 1.2 anbieten. Go schaltet die
// RSA-Schlüsselaustausch- und CBC-SHA256-Verfahren standardmäßig ab; ohne sie bricht so ein
// DC den Handshake kommentarlos ab. Für TLS 1.3 hat die Liste keine Bedeutung.
func cipherSuites() []uint16 {
	var ids []uint16
	for _, cs := range tls.CipherSuites() {
		ids = append(ids, cs.ID)
	}
	return append(ids,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	)
}

func isReset(err error) bool {
	m := strings.ToLower(err.Error())
	return strings.Contains(m, "reset") || strings.Contains(m, "eof") || strings.Contains(m, "wsarecv") || strings.Contains(m, "forcibly closed")
}

// Authenticate meldet den Benutzer am Domänencontroller an und prüft, ob er (auch über
// verschachtelte Gruppen) Mitglied der konfigurierten Gruppe ist. Geliefert wird der
// sAMAccountName, wie er im AD steht.
func Authenticate(c vault.ADConfig, user, password string) (string, error) {
	account, bindName := SplitUser(user, c.Domain)
	if account == "" || password == "" {
		return "", ErrBadCredentials // leeres Passwort wäre ein anonymer Bind und "gelingt" immer
	}
	addr, host, err := serverURL(c.Server)
	if err != nil {
		return "", err
	}
	tlsCfg := &tls.Config{ServerName: host, InsecureSkipVerify: c.SkipVerify, MinVersion: tls.VersionTLS12, CipherSuites: cipherSuites()}
	conn, err := ldap.DialURL(addr, ldap.DialWithTLSConfig(tlsCfg), ldap.DialWithDialer(&net.Dialer{Timeout: 8 * time.Second}))
	if err != nil {
		msg := fmt.Sprintf("Domänencontroller nicht erreichbar (%s): %v", addr, err)
		if strings.HasPrefix(addr, "ldaps://") && isReset(err) {
			msg += ". Der DC hat die verschlüsselte Verbindung abgebrochen. Meist hat er kein Zertifikat für LDAPS (Schannel-Ereignis 36886 auf dem DC) oder kein gemeinsames Verschlüsselungsverfahren (Ereignis 36874)."
		}
		return "", errors.New(msg)
	}
	defer conn.Close()
	conn.SetTimeout(10 * time.Second)
	if strings.HasPrefix(addr, "ldap://") {
		if err := conn.StartTLS(tlsCfg); err != nil {
			return "", fmt.Errorf("StartTLS fehlgeschlagen: %v", err)
		}
	}
	if err := conn.Bind(bindName, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return "", ErrBadCredentials
		}
		return "", fmt.Errorf("Anmeldung am Domänencontroller fehlgeschlagen: %v", err)
	}

	base := BaseDN(c)
	groupDN := c.Group
	if !strings.Contains(groupDN, "=") {
		res, err := conn.Search(ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 10, false,
			fmt.Sprintf("(&(objectCategory=group)(|(cn=%s)(sAMAccountName=%s)))", ldap.EscapeFilter(c.Group), ldap.EscapeFilter(c.Group)),
			[]string{"distinguishedName"}, nil))
		if err != nil {
			return "", fmt.Errorf("Gruppe %q konnte nicht gesucht werden: %v", c.Group, err)
		}
		if len(res.Entries) != 1 {
			return "", fmt.Errorf("Gruppe %q wurde im AD nicht (eindeutig) gefunden", c.Group)
		}
		groupDN = res.Entries[0].DN
	}

	who := fmt.Sprintf("(sAMAccountName=%s)", ldap.EscapeFilter(account))
	if strings.Contains(user, "@") {
		who = fmt.Sprintf("(userPrincipalName=%s)", ldap.EscapeFilter(strings.TrimSpace(user)))
	}
	// 1.2.840.113556.1.4.1941 = LDAP_MATCHING_RULE_IN_CHAIN: berücksichtigt verschachtelte Gruppen.
	filter := fmt.Sprintf("(&(objectCategory=person)(objectClass=user)%s(memberOf:1.2.840.113556.1.4.1941:=%s))", who, ldap.EscapeFilter(groupDN))
	res, err := conn.Search(ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 10, false,
		filter, []string{"sAMAccountName"}, nil))
	if err != nil {
		return "", fmt.Errorf("Gruppenmitgliedschaft konnte nicht geprüft werden: %v", err)
	}
	if len(res.Entries) != 1 {
		return "", ErrNotInGroup
	}
	if name := res.Entries[0].GetAttributeValue("sAMAccountName"); name != "" {
		return name, nil
	}
	return account, nil
}
