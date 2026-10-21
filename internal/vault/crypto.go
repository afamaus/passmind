package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const formatVersion = 1

// ErrBadCredentials wird zurückgegeben, wenn Passwort oder Schlüsseldatei falsch sind.
var ErrBadCredentials = errors.New("falsches Master-Passwort oder falsche Schlüsseldatei")

// KDFParams beschreibt die Argon2id-Parameter, mit denen der Schlüssel abgeleitet wird.
type KDFParams struct {
	Algorithm string `json:"alg"`
	Time      uint32 `json:"t"`
	MemoryKiB uint32 `json:"m"`
	Threads   uint8  `json:"p"`
	Salt      []byte `json:"salt"`
}

// Header steht unverschlüsselt am Anfang der Tresordatei und wird als
// zusätzliche authentifizierte Daten (AAD) in die Verschlüsselung einbezogen.
type Header struct {
	Version       int       `json:"version"`
	KDF           KDFParams `json:"kdf"`
	KeyFileNeeded bool      `json:"keyfile"`
	Cipher        string    `json:"cipher"`
	Nonce         []byte    `json:"nonce"`
}

type fileFormat struct {
	Header     string `json:"header"` // exakt die Bytes, die als AAD dienen
	Ciphertext []byte `json:"data"`
}

func defaultKDF() (KDFParams, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return KDFParams{}, err
	}
	return KDFParams{Algorithm: "argon2id", Time: 3, MemoryKiB: 64 * 1024, Threads: 4, Salt: salt}, nil
}

// deriveKey verbindet Master-Passwort und (optional) Schlüsseldatei zu einem 256-Bit-Schlüssel.
func deriveKey(password string, keyFile []byte, p KDFParams) ([]byte, error) {
	if p.Algorithm != "argon2id" {
		return nil, fmt.Errorf("unbekanntes KDF-Verfahren %q", p.Algorithm)
	}
	secret := []byte(password)
	if len(keyFile) > 0 {
		kf := sha256.Sum256(keyFile)
		mac := hmac.New(sha256.New, kf[:])
		mac.Write(secret)
		secret = mac.Sum(nil)
	}
	return argon2.IDKey(secret, p.Salt, p.Time, p.MemoryKiB, p.Threads, 32), nil
}

func seal(key []byte, plaintext []byte, keyFileNeeded bool, kdf KDFParams) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	h := Header{Version: formatVersion, KDF: kdf, KeyFileNeeded: keyFileNeeded, Cipher: "aes-256-gcm", Nonce: nonce}
	hb, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, hb)
	return json.MarshalIndent(fileFormat{Header: string(hb), Ciphertext: ct}, "", "  ")
}

// readHeader liest nur den unverschlüsselten Kopf, z. B. um zu wissen, ob eine Schlüsseldatei nötig ist.
func readHeader(raw []byte) (Header, fileFormat, error) {
	var ff fileFormat
	if err := json.Unmarshal(raw, &ff); err != nil {
		return Header{}, ff, fmt.Errorf("Tresordatei ist beschädigt: %w", err)
	}
	var h Header
	if err := json.Unmarshal([]byte(ff.Header), &h); err != nil {
		return Header{}, ff, fmt.Errorf("Tresorkopf ist beschädigt: %w", err)
	}
	if h.Version != formatVersion {
		return Header{}, ff, fmt.Errorf("Tresorversion %d wird nicht unterstützt", h.Version)
	}
	if h.Cipher != "aes-256-gcm" {
		return Header{}, ff, fmt.Errorf("unbekanntes Verschlüsselungsverfahren %q", h.Cipher)
	}
	return h, ff, nil
}

func open(raw []byte, password string, keyFile []byte) (plaintext []byte, key []byte, h Header, err error) {
	h, ff, err := readHeader(raw)
	if err != nil {
		return nil, nil, h, err
	}
	if h.KeyFileNeeded && len(keyFile) == 0 {
		return nil, nil, h, ErrBadCredentials
	}
	if !h.KeyFileNeeded {
		keyFile = nil
	}
	key, err = deriveKey(password, keyFile, h.KDF)
	if err != nil {
		return nil, nil, h, err
	}
	pt, err := decrypt(key, h, ff)
	if err != nil {
		return nil, nil, h, err
	}
	return pt, key, h, nil
}

// decrypt entschlüsselt den Inhalt mit einem bereits abgeleiteten Schlüssel.
func decrypt(key []byte, h Header, ff fileFormat) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(h.Nonce) != gcm.NonceSize() {
		return nil, errors.New("ungültige Nonce im Tresorkopf")
	}
	pt, err := gcm.Open(nil, h.Nonce, ff.Ciphertext, []byte(ff.Header))
	if err != nil {
		return nil, ErrBadCredentials
	}
	return pt, nil
}
