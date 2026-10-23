//go:build darwin

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/crgimenes/glaze"
	"github.com/crgimenes/glaze/menu"
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
	configureNativeMenu(w)
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

// configureNativeMenu installs the macOS application menu. The standard Edit
// selectors are required for Cmd+C/V/X/A/Z to reach the WKWebView; app-specific
// actions call the small bridge exposed by the web UI.
func configureNativeMenu(w glaze.WebView) {
	eval := func(js string) { w.Eval(js) }
	items := []menu.Item{
		{Title: "SSHVault", Submenu: []menu.Item{
			{Title: "Settings…", Shortcut: "cmd+,", OnClick: func() {
				eval("window.__sshvault?.openSettings()")
			}},
			{Separator: true},
			{Title: "Quit SSHVault", Shortcut: "cmd+q", OnClick: w.Terminate},
		}},
		{Title: "Edit", Submenu: []menu.Item{
			{Title: "Undo", Shortcut: "cmd+z", Selector: "undo:"},
			{Title: "Redo", Shortcut: "cmd+shift+z", Selector: "redo:"},
			{Separator: true},
			{Title: "Cut", Shortcut: "cmd+x", Selector: "cut:"},
			{Title: "Copy", Shortcut: "cmd+c", Selector: "copy:"},
			{Title: "Paste", Shortcut: "cmd+v", Selector: "paste:"},
			{Title: "Select All", Shortcut: "cmd+a", Selector: "selectAll:"},
			{Separator: true},
			{Title: "Services", Services: true},
		}},
		{Title: "Vault", Submenu: []menu.Item{
			{Title: "Open Existing Vault…", Shortcut: "cmd+o", OnClick: func() {
				eval("window.__sshvault?.openExistingVault()")
			}},
			{Title: "New Vault…", Shortcut: "cmd+n", OnClick: func() {
				eval("window.__sshvault?.openNewVault()")
			}},
			{Title: "Lock Vault", Shortcut: "cmd+l", OnClick: func() {
				eval("window.__sshvault?.lockVault()")
			}},
			{Separator: true},
			{Title: "Keyboard Shortcuts", Shortcut: "cmd+/", OnClick: func() {
				eval("window.__sshvault?.openShortcuts()")
			}},
		}},
		{Title: "Window", Submenu: []menu.Item{
			{Title: "Minimize", Shortcut: "cmd+m", Selector: "performMiniaturize:"},
			{Title: "Zoom", Selector: "performZoom:"},
			{Separator: true},
			{Title: "Close Window", Shortcut: "cmd+w", Selector: "performClose:"},
			{Title: "Bring All to Front", Selector: "arrangeInFront:"},
		}},
		{Title: "Help", Submenu: []menu.Item{
			{Title: "Keyboard Shortcuts", OnClick: func() {
				eval("window.__sshvault?.openShortcuts()")
			}},
			{Title: "GitHub Repository", OnClick: func() {
				openURL("https://github.com/lucasmenendez/sshvault")
			}},
		}},
	}
	if _, err := menu.Set(items, menu.Options{}); err != nil {
		fmt.Fprintln(os.Stderr, "Warning: cannot install native menu:", err)
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
