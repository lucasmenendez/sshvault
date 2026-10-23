package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/crgimenes/glaze"
	"golang.org/x/term"

	"sshvault/internal/preferences"
	"sshvault/internal/server"
	"sshvault/internal/sshutil"
	"sshvault/internal/vault"
)

var version = "dev"

func main() {
	// Cocoa requires the window and its run loop on the process main thread.
	// Keep the main goroutine pinned even while vault prompts or network setup
	// block before the optional Glaze window is created.
	runtime.LockOSThread()
	appMode := isAppMode()
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		if appMode {
			showAppError(err)
		}
		os.Exit(1)
	}
}

func isAppMode() bool {
	return os.Getenv("SSHVAULT_APP_MODE") == "1" ||
		strings.Contains(os.Args[0], ".app/Contents/MacOS/")
}

func run() error {
	var (
		fileFlag       string
		fileShort      string
		sshDirFlag     string
		addrFlag       string
		lockAfter      time.Duration
		openBrowser    bool
		uiMode         bool
		changePassword bool
		showVersion    bool
	)
	flag.StringVar(&fileFlag, "file", "", "vault file (default ~/.ssh/ssh.vault, or <ssh-dir>/ssh.vault)")
	flag.StringVar(&fileShort, "f", "", "vault file (shorthand)")
	flag.StringVar(&sshDirFlag, "ssh-dir", "", "SSH directory to manage (default ~/.ssh)")
	flag.StringVar(&addrFlag, "addr", "127.0.0.1:7000", "loopback listen address")
	flag.DurationVar(&lockAfter, "lock-after", 15*time.Minute, "lock the vault after inactivity (0 disables)")
	flag.BoolVar(&openBrowser, "open", false, "open the web UI in a browser")
	flag.BoolVar(&uiMode, "ui", false, "open the web UI in a native window")
	flag.BoolVar(&changePassword, "change-password", false, "change the vault password and exit")
	flag.BoolVar(&showVersion, "version", false, "print the version and exit")
	flag.Usage = usage
	flag.Parse()

	if showVersion {
		fmt.Printf("sshvault %s\n", version)
		return nil
	}
	if isAppMode() {
		uiMode = true
	}
	if lockAfter < 0 {
		return errors.New("--lock-after cannot be negative")
	}
	if uiMode && openBrowser {
		return errors.New("use either --ui or --open, not both")
	}
	if uiMode && changePassword {
		return errors.New("use either --ui or --change-password, not both")
	}

	if fileFlag != "" && fileShort != "" && fileFlag != fileShort {
		return errors.New("use either --file or -f, not both")
	}
	if fileFlag == "" {
		fileFlag = fileShort
	}
	args := flag.Args()
	if len(args) > 1 {
		return errors.New("too many arguments")
	}
	explicitVault := fileFlag
	if len(args) == 1 {
		if explicitVault != "" && explicitVault != args[0] {
			return errors.New("vault path given both as flag and argument")
		}
		explicitVault = args[0]
	}

	manager, err := sshutil.NewManager(sshDirFlag)
	if err != nil {
		return err
	}

	prefsPath, prefsErr := preferences.DefaultPath()
	var prefs *preferences.Manager
	if prefsErr == nil {
		prefs, prefsErr = preferences.Open(prefsPath)
	}
	if prefsErr != nil {
		fmt.Fprintf(os.Stderr, "Warning: cannot load preferences: %v\n", prefsErr)
	}

	vaultPath, defaultVault := chooseVaultPathWithPrefs(explicitVault, manager, prefs, sshDirFlag != "")
	if vaultPath == "" {
		return errors.New("empty vault path")
	}
	legacyHint := legacyVaultHint(vaultPath, defaultVault)
	if !changePassword {
		if _, err := os.Stat(vaultPath); os.IsNotExist(err) {
			if defaultVault {
				if err := manager.EnsureDir(); err != nil {
					return err
				}
			} else if err := os.MkdirAll(filepath.Dir(vaultPath), 0o700); err != nil {
				return fmt.Errorf("create vault directory: %w", err)
			}
		}
	}
	if changePassword {
		if _, err := os.Stat(vaultPath); err != nil {
			if os.IsNotExist(err) {
				msg := "cannot change the password: vault file not found"
				if legacyHint != "" {
					msg += "; a vault exists at " + legacyHint + " (use -f " + legacyHint + ")"
				}
				return errors.New(msg)
			}
			return err
		}
	}

	host, port, err := validateAddr(addrFlag)
	if err != nil {
		return err
	}

	var password string
	var store *vault.Store
	if changePassword {
		password, store, err = openVault(vaultPath, legacyHint)
	} else {
		if _, statErr := os.Stat(vaultPath); os.IsNotExist(statErr) {
			fmt.Printf("Vault not found: %s\n", vaultPath)
			if legacyHint != "" {
				fmt.Printf("A vault exists at %s; open it from the web UI or use -f %s.\n", legacyHint, legacyHint)
			}
		}
		store, err = vault.OpenLocked(vaultPath)
		if errors.Is(err, vault.ErrEmptyVault) {
			// An empty file is treated as an uninitialized vault path so the
			// web UI can offer to create it. Non-empty files are never touched.
			store, err = vault.OpenLockedForCreate(vaultPath)
		}
	}
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	if changePassword {
		next, err := promptNewPassword("New Vault Password: ", "Confirm Password: ")
		if err != nil {
			return err
		}
		if err := store.ChangePassword(password, next); err != nil {
			return err
		}
		fmt.Println("Password changed.")
		return nil
	}

	app := server.New(store, manager, store.Path(), manager.Dir, version, lockAfter)
	defer func() { _ = app.Close() }()
	app.SetPreferences(prefs)
	app.SetPort(port)

	primaryHost := host
	if primaryHost == "localhost" {
		primaryHost = "127.0.0.1"
	}
	primary, err := net.Listen("tcp", net.JoinHostPort(primaryHost, port))
	if err != nil {
		return fmt.Errorf("cannot listen on %s: %w", addrFlag, err)
	}
	actualPort := fmt.Sprintf("%d", primary.Addr().(*net.TCPAddr).Port)
	app.SetPort(actualPort)

	var listeners []net.Listener
	listeners = append(listeners, primary)
	if port != "0" {
		other := "::1"
		if primaryHost == "::1" {
			other = "127.0.0.1"
		}
		if ln, lerr := net.Listen("tcp", net.JoinHostPort(other, actualPort)); lerr == nil {
			listeners = append(listeners, ln)
		}
	}

	var window glaze.WebView
	if uiMode {
		window, err = glaze.NewWithOptions(glaze.Options{HideUntilLoaded: false})
		if err != nil {
			for _, ln := range listeners {
				_ = ln.Close()
			}
			return fmt.Errorf("cannot open the native UI: %w (try --open)", err)
		}
		defer window.Destroy()
		window.SetTitle("sshvault")
		window.SetSize(1280, 800, glaze.HintNone)
		configureNativeWindow(window)
		app.SetVaultPicker(func() (string, error) {
			return window.OpenFile(glaze.FileDialogOptions{
				Title:   "Open sshvault vault",
				Filters: []glaze.FileFilter{{Name: "sshvault vault", Extensions: []string{"vault"}}},
			})
		})
	}

	srv := &http.Server{
		Handler:           app.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, len(listeners))
	for _, ln := range listeners {
		go func(l net.Listener) {
			if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
			}
		}(ln)
	}

	url := fmt.Sprintf("http://localhost:%s", actualPort)
	fmt.Printf("Ok! Serving %s\n", url)
	if openBrowser {
		openURL(url)
	}

	if uiMode {
		window.Navigate(url)
		uiDone := make(chan error, 1)
		go func() {
			var reason error
			select {
			case <-ctx.Done():
			case reason = <-errCh:
			}
			uiDone <- reason
			window.Terminate()
		}()

		window.Run()
		stop()
		uiErr := <-uiDone

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		if uiErr != nil {
			return uiErr
		}
		return nil
	}

	select {
	case <-ctx.Done():
	case err := <-errCh:
		_ = srv.Close()
		return err
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	return nil
}

func openVault(path, legacyHint string) (string, *vault.Store, error) {
	if _, err := os.Stat(path); err != nil {
		if !os.IsNotExist(err) {
			return "", nil, err
		}
		fmt.Printf("Vault not found: %s\n", path)
		if legacyHint != "" {
			fmt.Printf("A vault exists at %s; use -f %s to open it.\n", legacyHint, legacyHint)
		}
		answer, err := readLine("Create a new vault? [y/N] ")
		if err != nil {
			return "", nil, err
		}
		if !strings.EqualFold(strings.TrimSpace(answer), "y") && !strings.EqualFold(strings.TrimSpace(answer), "yes") {
			return "", nil, errors.New("aborted")
		}
		password, err := promptNewPassword("New Vault Password: ", "Confirm Password: ")
		if err != nil {
			return "", nil, err
		}
		store, err := vault.Create(path, password)
		if err != nil {
			if errors.Is(err, vault.ErrVaultExists) {
				return "", nil, errors.New("the vault appeared while creating it; try again")
			}
			return "", nil, err
		}
		return password, store, nil
	}

	password, err := readPassword("Vault Password: ")
	if err != nil {
		return "", nil, err
	}
	store, err := vault.Open(path, password)
	if err != nil {
		switch {
		case errors.Is(err, vault.ErrInvalidPassword):
			return "", nil, errors.New("invalid password or corrupted vault")
		case errors.Is(err, vault.ErrInUse):
			return "", nil, errors.New("this vault is already open by another sshvault process")
		default:
			return "", nil, err
		}
	}
	return password, store, nil
}

func promptNewPassword(prompt, confirm string) (string, error) {
	for {
		first, err := readPassword(prompt)
		if err != nil {
			return "", err
		}
		if len(first) < 8 {
			fmt.Fprintln(os.Stderr, "The password must be at least 8 characters.")
			continue
		}
		second, err := readPassword(confirm)
		if err != nil {
			return "", err
		}
		if first != second {
			fmt.Fprintln(os.Stderr, "Passwords do not match. Try again.")
			continue
		}
		return first, nil
	}
}

func readPassword(prompt string) (string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stdout, prompt)
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stdout)
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	return readLine(prompt)
}

// readLine reads a single line byte by byte so it never consumes more input
// than the caller expects, which keeps password prompts predictable.
func readLine(prompt string) (string, error) {
	fmt.Fprint(os.Stdout, prompt)
	var b []byte
	buf := make([]byte, 1)
	for {
		n, err := os.Stdin.Read(buf)
		if n > 0 {
			switch buf[0] {
			case '\n':
				return string(b), nil
			case '\r':
			default:
				b = append(b, buf[0])
			}
		}
		if err != nil {
			if len(b) == 0 {
				return "", err
			}
			return string(b), nil
		}
	}
}

func chooseVaultPath(explicit string, manager *sshutil.Manager) (string, bool) {
	return chooseVaultPathWithPrefs(explicit, manager, nil, false)
}

func chooseVaultPathWithPrefs(explicit string, manager *sshutil.Manager, prefs *preferences.Manager, sshDirExplicit bool) (string, bool) {
	if explicit != "" {
		return explicit, false
	}
	if !sshDirExplicit && prefs != nil {
		cfg := prefs.Config()
		if cfg.RememberVault && usableVaultPath(cfg.LastVaultPath) {
			return cfg.LastVaultPath, false
		}
	}
	return filepath.Join(manager.Dir, "ssh.vault"), true
}

func usableVaultPath(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && info.Size() > 0
}

func legacyVaultHint(vaultPath string, defaultVault bool) string {
	if !defaultVault {
		return ""
	}
	if _, err := os.Stat(vaultPath); !os.IsNotExist(err) {
		return ""
	}
	const legacy = "./ssh.vault"
	if _, err := os.Stat(legacy); err == nil {
		return legacy
	}
	return ""
}

func validateAddr(addr string) (host, port string, err error) {
	host, port, err = net.SplitHostPort(addr)
	if err != nil {
		return "", "", fmt.Errorf("invalid --addr %q: %w", addr, err)
	}
	if port == "" {
		return "", "", errors.New("--addr must include a port")
	}
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1":
		return host, port, nil
	}
	return "", "", errors.New("--addr must be a loopback address (127.0.0.1, ::1 or localhost)")
}

func openURL(u string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", u)
	case "linux":
		cmd = exec.Command("xdg-open", u)
	default:
		return
	}
	_ = cmd.Start()
}

func usage() {
	out := flag.CommandLine.Output()
	fmt.Fprintf(out, "sshvault %s - encrypted SSH key and config manager\n\n", version)
	fmt.Fprintf(out, "Usage:\n  sshvault [flags] [vault-file]\n\n")
	fmt.Fprintf(out, "The default vault file is ~/.ssh/ssh.vault (or <ssh-dir>/ssh.vault)\n")
	fmt.Fprintf(out, "and the default SSH directory is ~/.ssh. The web UI is served on a\n")
	fmt.Fprintf(out, "loopback address only.\n\n")
	fmt.Fprintf(out, "Flags:\n")
	flag.PrintDefaults()
	fmt.Fprintf(out, "\nExamples:\n")
	fmt.Fprintf(out, "  sshvault\n")
	fmt.Fprintf(out, "  sshvault --ui\n")
	fmt.Fprintf(out, "  sshvault -f ./work.vault --ssh-dir ~/.ssh\n")
	fmt.Fprintf(out, "  sshvault --change-password\n")
}
