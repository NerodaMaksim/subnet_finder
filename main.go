package main

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"time"

	"github.com/NerodaMaksim/subnet_finder/internal/server"
)

//go:embed web
var webFS embed.FS

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	web, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatalf("embed web ui: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:8765")
	if err != nil {
		log.Printf("port 8765 busy, using a free port: %v", err)
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			log.Fatalf("listen: %v", err)
		}
	}

	url := fmt.Sprintf("http://%s", ln.Addr().String())
	log.Printf("subnet finder at %s", url)

	srv := &http.Server{Handler: server.New(web)}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("serve: %v", err)
		}
	}()

	if err := runAppWindow(url); err != nil {
		log.Printf("app window: %v", err)
		log.Printf("opening default browser; quit with Ctrl+C")
		if err := openBrowser(url); err != nil {
			log.Printf("open browser: %v", err)
		}
		waitInterrupt()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("shutdown: %v", err)
	}
}

func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}
