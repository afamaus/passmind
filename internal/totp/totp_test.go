package totp

import (
	"encoding/base32"
	"testing"
	"time"
)

// Testvektoren aus RFC 6238 (SHA-1), auf 6 Stellen gekürzt.
func TestRFC6238(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	cases := map[int64]string{59: "287082", 1111111109: "081804", 1234567890: "005924", 2000000000: "279037"}
	for ts, want := range cases {
		got, err := Code(secret, time.Unix(ts, 0))
		if err != nil || got != want {
			t.Errorf("t=%d: %s, erwartet %s (%v)", ts, got, want, err)
		}
	}
}

func TestVerifyWindow(t *testing.T) {
	s := NewSecret()
	now := time.Now()
	c, _ := Code(s, now.Add(-30*time.Second))
	if !Verify(s, c, now) {
		t.Fatal("vorheriges Zeitfenster sollte gelten")
	}
	c, _ = Code(s, now.Add(-120*time.Second))
	if Verify(s, c, now) {
		t.Fatal("alter Code darf nicht gelten")
	}
	if Verify(s, "abc", now) {
		t.Fatal("Unsinn darf nicht gelten")
	}
}

func TestRecoveryCodes(t *testing.T) {
	plain, hashes := NewRecoveryCodes(8)
	if len(plain) != 8 || len(hashes) != 8 {
		t.Fatal("falsche Anzahl")
	}
	if HashRecoveryCode(" "+plain[0][:3]+" "+plain[0][3:]+" ") != hashes[0] {
		t.Fatal("Normalisierung greift nicht")
	}
}
