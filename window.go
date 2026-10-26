package main

import (
	"os"
	"os/signal"
	"runtime"

	webview "github.com/webview/webview_go"
)

func init() {
	runtime.LockOSThread()
}

func runAppWindow(url string) error {
	w := webview.New(false)
	defer w.Destroy()
	w.SetTitle("Subnet Scanner")
	w.SetSize(920, 800, webview.HintNone)
	w.Navigate(url)
	w.Run()
	return nil
}

func waitInterrupt() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	defer signal.Stop(sig)
	<-sig
}
