package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// ErrBadCredentials wird zurückgegeben, wenn Benutzer, Passwort oder Schlüsseldatei falsch sind.
var ErrBadCredentials = errors.New("falsche Anmeldedaten")

// KDFParams beschreibt die Argon2id-Parameter, mit denen ein Schlüssel aus dem Passwort abgeleitet wird.
type KDFParams struct {
	Algorithm string `json:"alg"`
	Time      uint32 `json:"t"`
	MemoryKiB uint32 `json:"m"`
	Threads   uint8  `json:"p"`
	Salt      []byte `json:"salt"`
}

func defaultKDF() (KDFParams, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return KDFParams{}, err
	}
	return KDFParams{Algorithm: "argon2id", Time: 3, MemoryKiB: 64 * 1024, Threads: 4, Salt: salt}, nil
}

// deriveKey verbindet Passwort und (optional) Schlüsseldatei zu einem 256-Bit-Schlüssel.
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

func randomKey() []byte {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic(err)
	}
	return k
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Box ist ein mit AES-256-GCM verschlüsselter Wert.
type Box struct {
	Nonce []byte `json:"n"`
	CT    []byte `json:"c"`
}

func sealBox(key, plaintext []byte, aad string) (Box, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return Box{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Box{}, err
	}
	return Box{Nonce: nonce, CT: gcm.Seal(nil, nonce, plaintext, []byte(aad))}, nil
}

func openBox(key []byte, b Box, aad string) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(b.Nonce) != gcm.NonceSize() {
		return nil, ErrBadCredentials
	}
	pt, err := gcm.Open(nil, b.Nonce, b.CT, []byte(aad))
	if err != nil {
		return nil, ErrBadCredentials
	}
	return pt, nil
}

// SealedKey ist ein Schlüssel, der mit dem öffentlichen X25519-Schlüssel eines Benutzers
// verschlüsselt wurde (ephemeres ECDH + HKDF-SHA256 + AES-256-GCM).
type SealedKey struct {
	EphPub []byte `json:"e"`
	Box
}

func sealTo(pub []byte, secret []byte, aad string) (SealedKey, error) {
	rp, err := ecdh.X25519().NewPublicKey(pub)
	if err != nil {
		return SealedKey{}, err
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return SealedKey{}, err
	}
	shared, err := eph.ECDH(rp)
	if err != nil {
		return SealedKey{}, err
	}
	k, err := hkdf.Key(sha256.New, shared, append(eph.PublicKey().Bytes(), pub...), "passmind-seal", 32)
	if err != nil {
		return SealedKey{}, err
	}
	b, err := sealBox(k, secret, aad)
	return SealedKey{EphPub: eph.PublicKey().Bytes(), Box: b}, err
}

func openSealed(priv *ecdh.PrivateKey, s SealedKey, aad string) ([]byte, error) {
	ep, err := ecdh.X25519().NewPublicKey(s.EphPub)
	if err != nil {
		return nil, ErrBadCredentials
	}
	shared, err := priv.ECDH(ep)
	if err != nil {
		return nil, ErrBadCredentials
	}
	k, err := hkdf.Key(sha256.New, shared, append(append([]byte{}, s.EphPub...), priv.PublicKey().Bytes()...), "passmind-seal", 32)
	if err != nil {
		return nil, err
	}
	return openBox(k, s.Box, aad)
}
