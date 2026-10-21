package gen

import (
	"strings"
	"testing"
)

func TestGenerateChars(t *testing.T) {
	for i := 0; i < 200; i++ {
		r, err := Generate(Options{Length: 12, Lower: true, Upper: true, Digits: true, Symbols: true, ExcludeAmbiguous: true})
		if err != nil {
			t.Fatal(err)
		}
		pw := r.Password
		if len(pw) != 12 || !strings.ContainsAny(pw, lower) || !strings.ContainsAny(pw, upper) ||
			!strings.ContainsAny(pw, "23456789") || !strings.ContainsAny(pw, symbols) || strings.ContainsAny(pw, ambiguous) {
			t.Fatalf("Regel verletzt: %q", pw)
		}
	}
	if _, err := Generate(Options{Length: 12}); err == nil {
		t.Fatal("ohne Zeichengruppen muss ein Fehler kommen")
	}
}

func TestPassphrase(t *testing.T) {
	r, err := Generate(Options{Mode: "words", Words: 5, Separator: "_"})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(strings.Split(r.Password, "_")); n != 5 {
		t.Fatalf("%d Wörter in %q", n, r.Password)
	}
	if r.Entropy < 60 {
		t.Fatalf("Entropie zu niedrig: %v", r.Entropy)
	}
}
