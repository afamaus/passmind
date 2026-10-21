package ldapauth

import (
	"testing"

	"passmind/internal/vault"
)

func TestSplitUser(t *testing.T) {
	for _, c := range []struct{ in, acc, bind string }{
		{"anna", "anna", "anna@firma.local"},
		{`FIRMA\anna`, "anna", `FIRMA\anna`},
		{"anna@firma.local", "anna", "anna@firma.local"},
	} {
		if a, b := SplitUser(c.in, "firma.local"); a != c.acc || b != c.bind {
			t.Errorf("%q: %q %q", c.in, a, b)
		}
	}
}

func TestBaseDNAndURL(t *testing.T) {
	if got := BaseDN(vault.ADConfig{Domain: "firma.local"}); got != "DC=firma,DC=local" {
		t.Fatal(got)
	}
	for in, want := range map[string]string{"dc01": "ldaps://dc01:636", "ldap://dc01": "ldap://dc01:389", "ldaps://dc01:3269": "ldaps://dc01:3269"} {
		if got, _, _ := serverURL(in); got != want {
			t.Errorf("%s: %s", in, got)
		}
	}
}

func TestEmptyPasswordRejected(t *testing.T) {
	if _, err := Authenticate(vault.ADConfig{Server: "127.0.0.1:1", Domain: "x"}, "anna", ""); err != ErrBadCredentials {
		t.Fatal(err)
	}
}
