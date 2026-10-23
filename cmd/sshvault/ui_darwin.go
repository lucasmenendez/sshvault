//go:build darwin

package main

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/crgimenes/glaze"
	"github.com/ebitengine/purego/objc"
)

const (
	nsWindowStyleMaskFullSizeContentView = 1 << 15
	nsWindowTitleHidden                  = 1
	nsWindowTitlebarSeparatorStyleNone   = 0
)

// configureNativeWindow gives the macOS window an iTerm-style chrome: the
// titlebar is transparent and the content extends behind it, leaving only the
// traffic lights over the app background. The web app adds a matching top
// inset through the native-window class.
func configureNativeWindow(w glaze.WebView) {
	ptr := w.Window()
	if ptr == nil {
		return
	}
	w.Init(`document.documentElement.classList.add("native-window")`)
	win := objc.ID(uintptr(ptr))
	style := objc.Send[uint](win, objc.RegisterName("styleMask"))
	win.Send(objc.RegisterName("setStyleMask:"), style|nsWindowStyleMaskFullSizeContentView)
	win.Send(objc.RegisterName("setTitleVisibility:"), uint(nsWindowTitleHidden))
	win.Send(objc.RegisterName("setTitlebarAppearsTransparent:"), true)
	win.Send(objc.RegisterName("setMovableByWindowBackground:"), true)

	separator := objc.RegisterName("setTitlebarSeparatorStyle:")
	if objc.Send[bool](win, objc.RegisterName("respondsToSelector:"), separator) {
		win.Send(separator, uint(nsWindowTitlebarSeparatorStyleNone))
	}
}

// showAppError is used when the app is launched from Finder and has no
// terminal attached, so startup errors are still visible.
func showAppError(err error) {
	msg := strings.ReplaceAll(err.Error(), `\`, `\\`)
	msg = strings.ReplaceAll(msg, `"`, `\"`)
	script := fmt.Sprintf(`display alert "SSHVault" message "%s" as critical`, msg)
	_ = exec.Command("osascript", "-e", script).Run()
}
