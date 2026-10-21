// PassMind: portabler, lokaler Passwort-Manager mit Weboberfläche.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"

	"passmind/internal/server"
	"passmind/web"
)

var version = "dev"

func main() {
	defaultVault := "passmind.vault"
	if exe, err := os.Executable(); err == nil {
		if real, err := filepath.EvalSymlinks(exe); err == nil {
			exe = real
		}
		defaultVault = filepath.Join(filepath.Dir(exe), defaultVault)
	}
	vaultPath := flag.String("vault", "", "Pfad zur Tresordatei (Standard: zuletzt verwendeter Tresor, sonst passmind.vault neben dem Programm)")
	port := flag.String("port", "0", "Port auf 127.0.0.1 (0 = automatisch)")
	noBrowser := flag.Bool("no-browser", false, "Browser nicht automatisch öffnen")
	showVersion := flag.Bool("version", false, "Version anzeigen")
	flag.Parse()

	if *showVersion {
		fmt.Println("PassMind", version)
		return
	}
	configPath := server.ConfigPath(filepath.Dir(defaultVault))
	chosen := *vaultPath
	if chosen == "" {
		chosen = server.LoadConfig(configPath).VaultPath
	}
	if chosen == "" {
		chosen = defaultVault
	}
	abs, err := filepath.Abs(chosen)
	if err != nil {
		log.Fatal(err)
	}

	srv := server.New(abs, configPath, web.Static())
	ln, url, err := srv.Listen(*port)
	if err != nil {
		log.Fatalf("Port konnte nicht geöffnet werden: %v", err)
	}

	fmt.Println("PassMind", version)
	fmt.Println("Tresor:", abs)
	fmt.Println()
	fmt.Println("Oberfläche im Browser öffnen:")
	fmt.Println("  " + url)
	fmt.Println()
	fmt.Println("Dieses Fenster offen lassen. Beenden mit Strg+C oder über \"Beenden\" in der Oberfläche.")

	if !*noBrowser {
		if err := openBrowser(url); err != nil {
			fmt.Println("Browser konnte nicht automatisch geöffnet werden, bitte Adresse oben manuell öffnen.")
		}
	}

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt)
		<-sig
		srv.Shutdown()
	}()

	if err := srv.Serve(ln); err != nil {
		log.Fatal(err)
	}
	fmt.Println("PassMind beendet, Tresor gesperrt.")
}

func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}
