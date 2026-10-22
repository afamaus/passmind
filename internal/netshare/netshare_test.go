package netshare

import "testing"

func TestShareRoot(t *testing.T) {
	for in, want := range map[string]string{
		`\\nas\daten\passmind\passmind.vault`: `\\nas\daten`,
		`\\nas\daten`:                         `\\nas\daten`,
		`//nas/daten/x.vault`:                 `\\nas\daten`,
		`\\nas`:                               "",
		`C:\daten\x.vault`:                    "",
		`\\?\C:\x`:                            "",
	} {
		got, ok := ShareRoot(in)
		if got != want || ok != (want != "") {
			t.Errorf("ShareRoot(%q) = %q, %v; erwartet %q", in, got, ok, want)
		}
	}
}
