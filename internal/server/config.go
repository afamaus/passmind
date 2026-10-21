package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
)

// Config wird als passmind.json gespeichert und merkt sich den zuletzt verwendeten Tresor.
type Config struct {
	VaultPath string   `json:"vaultPath,omitempty"`
	Recent    []string `json:"recent,omitempty"`
}

const maxRecent = 6

// ConfigPath liefert den Ort der Konfigurationsdatei: neben dem Programm, wenn dort
// geschrieben werden kann (portabler Betrieb), sonst im Konfigurationsordner des Benutzers.
func ConfigPath(exeDir string) string {
	local := filepath.Join(exeDir, "passmind.json")
	if _, err := os.Stat(local); err == nil {
		return local
	}
	if f, err := os.CreateTemp(exeDir, ".passmind-*.tmp"); err == nil {
		f.Close()
		os.Remove(f.Name())
		return local
	}
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "PassMind", "passmind.json")
	}
	return local
}

// LoadConfig liest die Konfiguration; fehlt sie, gibt es eine leere.
func LoadConfig(path string) Config {
	var c Config
	if b, err := os.ReadFile(path); err == nil {
		json.Unmarshal(b, &c)
	}
	return c
}

func (c *Config) remember(vaultPath string) {
	c.VaultPath = vaultPath
	c.Recent = slices.DeleteFunc(c.Recent, func(p string) bool { return p == vaultPath })
	c.Recent = append([]string{vaultPath}, c.Recent...)
	if len(c.Recent) > maxRecent {
		c.Recent = c.Recent[:maxRecent]
	}
}

func (c Config) save(path string) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	return os.WriteFile(path, b, 0o600)
}
