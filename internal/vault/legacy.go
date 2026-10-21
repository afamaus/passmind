package vault

import (
	"encoding/json"
	"fmt"
)

// Tresore im Format 1 (ein Master-Passwort, ohne Benutzer) werden beim ersten Öffnen
// automatisch ins Format 2 übernommen.

type headerV1 struct {
	Version       int       `json:"version"`
	KDF           KDFParams `json:"kdf"`
	KeyFileNeeded bool      `json:"keyfile"`
	Cipher        string    `json:"cipher"`
	Nonce         []byte    `json:"nonce"`
}

type fileV1 struct {
	Header     string `json:"header"`
	Ciphertext []byte `json:"data"`
}

func openV1(raw []byte, password string, keyFile []byte) (Data, error) {
	var ff fileV1
	if err := json.Unmarshal(raw, &ff); err != nil {
		return Data{}, fmt.Errorf("Tresordatei ist beschädigt: %w", err)
	}
	var h headerV1
	if err := json.Unmarshal([]byte(ff.Header), &h); err != nil {
		return Data{}, fmt.Errorf("Tresorkopf ist beschädigt: %w", err)
	}
	if h.KeyFileNeeded && len(keyFile) == 0 {
		return Data{}, ErrBadCredentials
	}
	if !h.KeyFileNeeded {
		keyFile = nil
	}
	key, err := deriveKey(password, keyFile, h.KDF)
	if err != nil {
		return Data{}, err
	}
	pt, err := openBox(key, Box{Nonce: h.Nonce, CT: ff.Ciphertext}, ff.Header)
	if err != nil {
		return Data{}, err
	}
	var d Data
	err = json.Unmarshal(pt, &d)
	clear(pt)
	if err != nil {
		return Data{}, fmt.Errorf("Tresorinhalt ist beschädigt")
	}
	return d, nil
}
