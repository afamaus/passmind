// Package totp implementiert zeitbasierte Einmalpasswörter nach RFC 6238 (SHA-1, 6 Stellen, 30 s),
// kompatibel mit gängigen Authenticator-Apps.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	period = 30
	digits = 6
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret erzeugt ein zufälliges 160-Bit-Geheimnis in Base32.
func NewSecret() string {
	b := make([]byte, 20)
	rand.Read(b)
	return b32.EncodeToString(b)
}

// URI liefert die otpauth://-Adresse für den QR-Code.
func URI(secret, issuer, account string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(digits))
	q.Set("period", fmt.Sprint(period))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// Code berechnet den Code für einen Zeitpunkt.
func Code(secret string, t time.Time) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", err
	}
	return code(key, uint64(t.Unix()/period)), nil
}

func code(key []byte, counter uint64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", digits, v%1000000)
}

// Verify prüft einen Code und erlaubt eine Abweichung von ±1 Zeitfenster.
func Verify(secret, input string, t time.Time) bool {
	input = strings.ReplaceAll(strings.TrimSpace(input), " ", "")
	if len(input) != digits {
		return false
	}
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return false
	}
	c := uint64(t.Unix() / period)
	ok := 0
	for _, d := range []int64{-1, 0, 1} {
		ok |= subtle.ConstantTimeCompare([]byte(code(key, uint64(int64(c)+d))), []byte(input))
	}
	return ok == 1
}

// NewRecoveryCodes erzeugt n lesbare Wiederherstellungscodes und deren Hashes zum Speichern.
func NewRecoveryCodes(n int) (plain []string, hashes []string) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	for i := 0; i < n; i++ {
		b := make([]byte, 10)
		rand.Read(b)
		var sb strings.Builder
		for j, x := range b {
			if j == 5 {
				sb.WriteByte('-')
			}
			sb.WriteByte(alphabet[int(x)%len(alphabet)])
		}
		plain = append(plain, sb.String())
		hashes = append(hashes, HashRecoveryCode(sb.String()))
	}
	return
}

// HashRecoveryCode normalisiert und hasht einen Wiederherstellungscode.
func HashRecoveryCode(c string) string {
	c = strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(c)))
	s := sha256.Sum256([]byte(c))
	return hex.EncodeToString(s[:])
}
