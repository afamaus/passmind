// Package gen erzeugt zufällige Passwörter und Passphrasen mit crypto/rand.
package gen

import (
	"crypto/rand"
	_ "embed"
	"errors"
	"math"
	"math/big"
	"strings"
)

//go:embed words.txt
var wordData string

var words = strings.Fields(wordData)

const (
	lower     = "abcdefghijklmnopqrstuvwxyz"
	upper     = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digitsSet = "0123456789"
	symbols   = "!#$%&()*+,-./:;<=>?@[]^_{|}~"
	ambiguous = "Il1O0o"
)

// Options steuert den Generator.
type Options struct {
	Mode             string `json:"mode"` // "chars" oder "words"
	Length           int    `json:"length"`
	Lower            bool   `json:"lower"`
	Upper            bool   `json:"upper"`
	Digits           bool   `json:"digits"`
	Symbols          bool   `json:"symbols"`
	ExcludeAmbiguous bool   `json:"excludeAmbiguous"`
	Words            int    `json:"words"`
	Separator        string `json:"separator"`
}

// Result enthält das Passwort und die geschätzte Entropie in Bit.
type Result struct {
	Password string  `json:"password"`
	Entropy  float64 `json:"entropy"`
}

func randInt(n int) int {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		panic(err)
	}
	return int(v.Int64())
}

func filter(set string, drop bool) string {
	if !drop {
		return set
	}
	return strings.Map(func(r rune) rune {
		if strings.ContainsRune(ambiguous, r) {
			return -1
		}
		return r
	}, set)
}

// Generate erzeugt ein Passwort gemäß den Optionen.
func Generate(o Options) (Result, error) {
	if o.Mode == "words" {
		return passphrase(o)
	}
	if o.Length < 4 || o.Length > 256 {
		return Result{}, errors.New("Länge muss zwischen 4 und 256 liegen")
	}
	var groups []string
	if o.Lower {
		groups = append(groups, filter(lower, o.ExcludeAmbiguous))
	}
	if o.Upper {
		groups = append(groups, filter(upper, o.ExcludeAmbiguous))
	}
	if o.Digits {
		groups = append(groups, filter(digitsSet, o.ExcludeAmbiguous))
	}
	if o.Symbols {
		groups = append(groups, symbols)
	}
	if len(groups) == 0 {
		return Result{}, errors.New("mindestens eine Zeichengruppe auswählen")
	}
	all := strings.Join(groups, "")
	pw := make([]byte, o.Length)
	// Aus jeder gewählten Gruppe mindestens ein Zeichen, Rest beliebig, dann mischen.
	for i := range pw {
		if i < len(groups) {
			pw[i] = groups[i][randInt(len(groups[i]))]
		} else {
			pw[i] = all[randInt(len(all))]
		}
	}
	for i := len(pw) - 1; i > 0; i-- {
		j := randInt(i + 1)
		pw[i], pw[j] = pw[j], pw[i]
	}
	return Result{Password: string(pw), Entropy: float64(o.Length) * math.Log2(float64(len(all)))}, nil
}

func passphrase(o Options) (Result, error) {
	if o.Words < 3 || o.Words > 20 {
		return Result{}, errors.New("Wortanzahl muss zwischen 3 und 20 liegen")
	}
	sep := o.Separator
	if sep == "" {
		sep = "-"
	}
	parts := make([]string, o.Words)
	for i := range parts {
		w := words[randInt(len(words))]
		if o.Upper {
			w = strings.ToUpper(w[:1]) + w[1:]
		}
		parts[i] = w
	}
	entropy := float64(o.Words) * math.Log2(float64(len(words)))
	if o.Digits {
		parts[randInt(len(parts))] += string(digitsSet[randInt(10)])
		entropy += math.Log2(10 * float64(o.Words))
	}
	return Result{Password: strings.Join(parts, sep), Entropy: entropy}, nil
}
