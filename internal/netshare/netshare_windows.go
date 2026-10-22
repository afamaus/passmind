package netshare

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Supported meldet, ob PassMind Freigaben selbst verbinden kann.
const Supported = true

var (
	mpr                      = windows.NewLazySystemDLL("mpr.dll")
	procWNetAddConnection2   = mpr.NewProc("WNetAddConnection2W")
	procWNetCancelConnection = mpr.NewProc("WNetCancelConnection2W")
)

type netResource struct {
	Scope       uint32
	Type        uint32
	DisplayType uint32
	Usage       uint32
	LocalName   *uint16
	RemoteName  *uint16
	Comment     *uint16
	Provider    *uint16
}

const (
	resourceTypeDisk       = 1
	errSessionCredConflict = 1219
	errAlreadyAssigned     = 85
	errLogonFailure        = 1326
	errBadNetName          = 67
	errBadNetPath          = 53
	errAccountRestriction  = 1327
	errPasswordExpired     = 1330
	errAccountDisabled     = 1331
	errAccountLockedOut    = 1909
)

// Connect verbindet die Freigabe (z. B. \\nas\daten) mit Benutzer und Passwort, ohne
// Laufwerksbuchstaben. Die Verbindung gilt für die Windows-Anmeldesitzung.
func Connect(share, user, password string) error {
	remote, err := windows.UTF16PtrFromString(share)
	if err != nil {
		return err
	}
	u, err := windows.UTF16PtrFromString(user)
	if err != nil {
		return err
	}
	pw, err := windows.UTF16PtrFromString(password)
	if err != nil {
		return err
	}
	nr := netResource{Type: resourceTypeDisk, RemoteName: remote}
	r, _, _ := procWNetAddConnection2.Call(uintptr(unsafe.Pointer(&nr)), uintptr(unsafe.Pointer(pw)), uintptr(unsafe.Pointer(u)), 0)
	switch r {
	case 0, errAlreadyAssigned:
		return nil
	case errSessionCredConflict:
		return errors.New("Windows ist mit diesem Server schon unter einem anderen Benutzer verbunden (z. B. über ein verbundenes Laufwerk). Windows erlaubt pro Server nur einen Benutzer. Entweder die andere Verbindung trennen (net use) oder Verbindungsart „Standard“ wählen.")
	case errLogonFailure:
		return errors.New("Anmeldung an der Freigabe fehlgeschlagen: Benutzername oder Passwort ist falsch.")
	case errBadNetName, errBadNetPath:
		return fmt.Errorf("Freigabe %s wurde nicht gefunden. Server und Freigabenamen prüfen.", share)
	case errAccountRestriction, errPasswordExpired, errAccountDisabled, errAccountLockedOut:
		return fmt.Errorf("Anmeldung an der Freigabe abgelehnt: %v", syscall.Errno(r))
	default:
		return fmt.Errorf("Freigabe %s konnte nicht verbunden werden: %v", share, syscall.Errno(r))
	}
}

// Disconnect trennt eine von Connect hergestellte Verbindung.
func Disconnect(share string) {
	remote, err := windows.UTF16PtrFromString(share)
	if err != nil {
		return
	}
	procWNetCancelConnection.Call(uintptr(unsafe.Pointer(remote)), 0, 1)
}

var entropy = []byte("PassMind-Netzwerkfreigabe")

// Protect verschlüsselt ein Geheimnis für den angemeldeten Windows-Benutzer (DPAPI).
// Nur dieser Benutzer kann es auf diesem Rechner wieder lesen.
func Protect(secret []byte) ([]byte, error) {
	in := windows.DataBlob{Size: uint32(len(secret))}
	if len(secret) > 0 {
		in.Data = &secret[0]
	}
	ent := windows.DataBlob{Size: uint32(len(entropy)), Data: &entropy[0]}
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, &ent, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}

// Unprotect entschlüsselt ein mit Protect geschütztes Geheimnis.
func Unprotect(blob []byte) ([]byte, error) {
	if len(blob) == 0 {
		return nil, errors.New("leer")
	}
	in := windows.DataBlob{Size: uint32(len(blob)), Data: &blob[0]}
	ent := windows.DataBlob{Size: uint32(len(entropy)), Data: &entropy[0]}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, &ent, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}
