// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/jeremiahjrross/podaro/internal/auth"
	"github.com/jeremiahjrross/podaro/internal/config"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/render"
	"github.com/jeremiahjrross/podaro/internal/state"
	"github.com/jeremiahjrross/podaro/internal/system"
)

func newAuth() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "the operator account and API tokens",
	}
	cmd.AddCommand(newAuthSetup(false), newAuthSetup(true), newAuthToken())
	return cmd
}

// newAuthSetup is INSTALL §2 step 5 (`auth setup`) and its socket-only
// recovery (`auth reset`): the password is read with echo off, checked,
// and sent to the engine over the local socket, which hashes it with
// Argon2id into auth.json and audits the act.
func newAuthSetup(reset bool) *cobra.Command {
	var username, passwordFile string
	use, short := "setup", "create the operator account (username + password)"
	if reset {
		use, short = "reset", "replace the operator account and sign every session out (local socket only)"
	}
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			p := render.Detect(os.Stdout)
			if username == "" {
				def := defaultUsername()
				if !isTerminal(os.Stdin) {
					username = def
				} else {
					fmt.Printf("username [%s]: ", def)
					line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
					username = strings.TrimSpace(line)
					if username == "" {
						username = def
					}
				}
			}
			password, err := readPassword(passwordFile)
			if err != nil {
				return err
			}
			if err := auth.CheckPassword(password); err != nil {
				return jsonOrErr(err, 2)
			}
			c := newClient()
			if err := c.SetOperator(context.Background(), username, password, reset); err != nil {
				return jsonOrErr(err, 1)
			}
			if jsonOut {
				return json.NewEncoder(os.Stdout).Encode(map[string]any{"operator": map[string]any{"username": username, "reset": reset}})
			}
			cfg, _ := config.Load(config.Path())
			url := ""
			if cfg != nil && cfg.Domain != "" {
				url = system.ConsoleURL(cfg.Domain, cfg.Gateway.Port)
			}
			system.RenderAuthSetupBlock(p, reset, url)
			return nil
		},
	}
	cmd.Flags().StringVar(&username, "username", "", "operator username (default: your login name; prompted on a TTY)")
	cmd.Flags().StringVar(&passwordFile, "password-file", "", "read the password from this file instead of prompting (scripts; never a flag value)")
	return cmd
}

func defaultUsername() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return os.Getenv("USER")
}

// readPassword reads the password with echo off, twice (INSTALL §2
// step 5), or from a file for scripts.
func readPassword(file string) (string, error) {
	if file != "" {
		// The file is judged by the descriptor it is read from — a regular
		// file no one else can read (INSTALL §2 step 5: 0600) — before a
		// byte of it is read: a password another user of this host could
		// read is refused, not accepted and left exposed.
		f, err := os.Open(file)
		if err != nil {
			e := pdr.New(pdr.CodePasswordPolicy, "cannot read --password-file %s", file)
			e.Cause = err.Error()
			return "", e
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil {
			e := pdr.New(pdr.CodePasswordPolicy, "cannot read --password-file %s", file)
			e.Cause = err.Error()
			return "", e
		}
		if !info.Mode().IsRegular() {
			e := pdr.New(pdr.CodePasswordPolicy, "--password-file %s is not a regular file", file)
			e.Next = "pass a 0600 file holding the password on one line"
			return "", e
		}
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			e := pdr.New(pdr.CodePasswordPolicy, "--password-file %s is readable by others (mode %04o)", file, perm)
			e.Cause = "a password file must be 0600: other users of this host could read the operator password"
			e.Next = "chmod 0600 " + file + " and re-run"
			return "", e
		}
		raw, err := io.ReadAll(io.LimitReader(f, 64<<10))
		if err != nil {
			e := pdr.New(pdr.CodePasswordPolicy, "cannot read --password-file %s", file)
			e.Cause = err.Error()
			return "", e
		}
		return strings.TrimRight(string(raw), "\r\n"), nil
	}
	if !isTerminal(os.Stdin) {
		e := pdr.New(pdr.CodePasswordPolicy, "no terminal to prompt for the password")
		e.Next = "run interactively, or pass --password-file <0600 file>"
		return "", e
	}
	fmt.Print("password (12+ characters, not displayed): ")
	first, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", err
	}
	if err := auth.CheckPassword(string(first)); err != nil {
		return "", err
	}
	fmt.Print("confirm: ")
	second, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", err
	}
	if string(first) != string(second) {
		e := pdr.New(pdr.CodePasswordPolicy, "the passwords do not match")
		e.Next = "run podaro auth setup again"
		return "", e
	}
	return string(first), nil
}

// tokenNamed finds a listed token by name.
func tokenNamed(tokens []state.Token, name string) *state.Token {
	for i := range tokens {
		if tokens[i].Name == name {
			return &tokens[i]
		}
	}
	return nil
}

// definitive reports whether an error from the engine is its answer — an
// envelope it wrote — rather than a transport failure (the socket
// unreachable, a response cut off) after which its outcome is unknown.
func definitive(err error) bool {
	var pe *pdr.Error
	return errors.As(err, &pe) && pe.Code != pdr.CodeEngineUnavailable
}

// saveSecret lands the secret at path — created exclusively, 0600, synced,
// its directory synced too — so it is durable before the token exists.
// created reports whether this call made the file: a path that already
// exists is not this run's to remove.
func saveSecret(dir, path, secret string) (created bool, err error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return false, err
	}
	_, err = f.WriteString(secret + "\n")
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(path, 0o600)
	}
	if err != nil {
		return true, err
	}
	d, err := os.Open(dir)
	if err != nil {
		return true, err
	}
	defer d.Close()
	return true, d.Sync()
}

// tokenFileErr is the refusal for a tokens directory or file that cannot
// hold the secret (PDR-E204 with the path as the cause).
func tokenFileErr(path string, err error) *pdr.Error {
	e := pdr.New(pdr.CodeRuntimeFailed, "cannot save the token secret at %s", tildify(path))
	e.Cause = err.Error()
	e.Next = "fix the tokens directory (or remove the stale file) and re-run · or --show to print the secret once"
	return e
}

// newAuthToken is API §2.3: create/list/revoke scoped bearer tokens.
func newAuthToken() *cobra.Command {
	cmd := &cobra.Command{Use: "token", Short: "scoped API tokens (read · operate · admin)"}
	var name, scope string
	var show bool
	create := &cobra.Command{
		Use:   "create --name <name> --scope <scope>",
		Short: "issue a token; written to the tokens directory (0600) unless --show",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if name == "" {
				e := pdr.New(pdr.CodePasswordPolicy, "--name is required")
				e.Next = "podaro auth token create --name ci --scope read"
				return jsonOrErr(e, 2)
			}
			// The name policy is applied here, before the name ever
			// becomes a path: a name that escapes the tokens directory is
			// refused before any file is looked at, let alone removed.
			if err := auth.CheckUsername(name); err != nil {
				e := pdr.New(pdr.CodePasswordPolicy, "token name %q: lowercase letters, digits, '-', '.', '_' only, 1–32 characters", name)
				e.Next = "podaro auth token create --name ci --scope read"
				return jsonOrErr(e, 2)
			}
			ctx := context.Background()
			c := newClient()
			if jsonOut || show {
				// The secret is made here and the token minted with it, as
				// for the file-backed path (API §2.3): an answer lost on the
				// socket loses no credential — the list says whether the
				// engine minted the token, under this secret's prefix, and
				// the secret is still in hand to print.
				secret, err := auth.NewTokenSecret()
				if err != nil {
					return jsonOrErr(err, 1)
				}
				tok, err := c.CreateTokenWithSecret(ctx, name, scope, secret)
				if err != nil {
					if definitive(err) {
						return jsonOrErr(err, 1)
					}
					// A token listed under this secret's prefix is this one; one
					// under another prefix is not. No token listed settles
					// nothing — the list may have overtaken the creation still
					// running on the engine — so the secret is printed with the
					// answer that it is unknown, never suppressed.
					tokens, lerr := c.Tokens(ctx)
					t := tokenNamed(tokens, name)
					if lerr != nil || t == nil {
						e := pdr.New(pdr.CodeRuntimeFailed, "the engine's answer to creating token %q is unknown", name)
						e.Cause = err.Error()
						e.Next = "the secret is " + secret + " (prefix " + auth.SecretPrefix(secret) + ") · podaro auth token list once the engine answers: a token named " + name + " under that prefix is this one; none means it was not created"
						return jsonOrErr(e, 1)
					}
					if t.Prefix != auth.SecretPrefix(secret) {
						e := pdr.New(pdr.CodeTokenExists, "a token named %q was created meanwhile with another secret; this one was not", name)
						e.Cause = err.Error()
						e.Next = "podaro auth token revoke " + name + " · or choose another name"
						return jsonOrErr(e, 1)
					}
					tok = t
				}
				if jsonOut {
					return json.NewEncoder(os.Stdout).Encode(map[string]any{"token": tok, "secret": secret})
				}
				render.Detect(os.Stdout).Plain(secret)
				return nil
			}
			// File-backed (API §2.3): the secret is made here and durable
			// on disk before the token exists, and the engine stores only
			// its hash — so a crash at any point leaves either a stale file
			// without a token, reclaimed by the next create of the name,
			// or a live token whose secret is already saved; never a live
			// token nobody holds.
			dir := filepath.Join(config.StateDir(), "tokens")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return jsonOrErr(tokenFileErr(dir, err), 1)
			}
			path := filepath.Join(dir, name+".token")
			held, err := os.ReadFile(path)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				// Something is there and cannot be read — a file whose secret
				// may be a live token's only copy. It is left exactly as it
				// is, never treated as absent.
				return jsonOrErr(tokenFileErr(path, err), 1)
			}
			if err == nil {
				// A file already holds a secret for this name: the live
				// token's — its listed prefix says so — or an interrupted
				// run's, which no token matches.
				tokens, err := c.Tokens(ctx)
				if err != nil {
					return jsonOrErr(err, 1)
				}
				if t := tokenNamed(tokens, name); t != nil {
					saved := strings.TrimSpace(string(held))
					if auth.SecretPrefix(saved) == t.Prefix {
						if !auth.WellFormedSecret(saved) {
							// The listed prefix is this file's, but what follows
							// it is not a secret's shape — truncated, a partial
							// restore: the token cannot be used from this file,
							// which is left exactly as it is.
							e := pdr.New(pdr.CodeTokenExists, "a token named %q already exists, but %s does not hold a usable secret (not a token secret's shape)", name, tildify(path))
							e.Next = "podaro auth token revoke " + name + " · then create it again"
							return jsonOrErr(e, 1)
						}
						e := pdr.New(pdr.CodeTokenExists, "a token named %q already exists; its secret is in %s", name, tildify(path))
						e.Next = "podaro auth token revoke " + name + " · or choose another name"
						return jsonOrErr(e, 1)
					}
					os.Remove(path)
					e := pdr.New(pdr.CodeTokenExists, "a token named %q already exists; %s did not hold its secret and was removed", name, tildify(path))
					e.Next = "podaro auth token revoke " + name + " · or choose another name"
					return jsonOrErr(e, 1)
				}
				if err := os.Remove(path); err != nil {
					return jsonOrErr(tokenFileErr(path, err), 1)
				}
			}
			secret, err := auth.NewTokenSecret()
			if err != nil {
				return jsonOrErr(err, 1)
			}
			if created, err := saveSecret(dir, path, secret); err != nil {
				if created {
					os.Remove(path) // only what this run created
				}
				return jsonOrErr(tokenFileErr(path, err), 1)
			}
			if _, err := c.CreateTokenWithSecret(ctx, name, scope, secret); err != nil {
				if definitive(err) {
					// The engine answered and refused: nothing was minted.
					os.Remove(path)
					return jsonOrErr(err, 1)
				}
				// The engine's answer never arrived — the connection dropped
				// before or after it minted the token. The file is the only
				// copy of the secret, so it stays until the engine says which:
				// a token listed under this file's prefix was written; one
				// under another prefix means this one was not, and the file
				// goes; no token listed settles nothing — the list may have
				// overtaken the creation still running on the engine — so the
				// file stays for the next create of the name to reconcile,
				// as it does when the engine cannot say.
				if tokens, lerr := c.Tokens(ctx); lerr == nil {
					if t := tokenNamed(tokens, name); t != nil {
						// The name alone proves nothing — another client may
						// have minted it meanwhile; the listed prefix is what
						// ties the token to this file's secret.
						if t.Prefix == auth.SecretPrefix(secret) {
							render.Detect(os.Stdout).NextAction(fmt.Sprintf("token written to %s (0600)", tildify(path)))
							return nil
						}
						os.Remove(path)
						e := pdr.New(pdr.CodeTokenExists, "a token named %q was created meanwhile with another secret; this one was not", name)
						e.Cause = err.Error()
						e.Next = "podaro auth token revoke " + name + " · or choose another name"
						return jsonOrErr(e, 1)
					}
				}
				e := pdr.New(pdr.CodeRuntimeFailed, "the engine's answer to creating token %q is unknown", name)
				e.Cause = err.Error()
				e.Next = "the secret stays in " + tildify(path) + " · re-run podaro auth token create --name " + name + " once the engine answers: it reports the token if it exists and reclaims the file if not"
				return jsonOrErr(e, 1)
			}
			render.Detect(os.Stdout).NextAction(fmt.Sprintf("token written to %s (0600)", tildify(path)))
			return nil
		},
	}
	create.Flags().StringVar(&name, "name", "", "token name (unique; the file and listing name)")
	create.Flags().StringVar(&scope, "scope", auth.ScopeRead, "read | operate | admin")
	create.Flags().BoolVar(&show, "show", false, "print the token once instead of writing the file")

	list := &cobra.Command{
		Use:   "list",
		Short: "tokens by name, prefix, scope, last use (never the secrets)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			tokens, err := newClient().Tokens(context.Background())
			if err != nil {
				return jsonOrErr(err, 1)
			}
			if jsonOut {
				return json.NewEncoder(os.Stdout).Encode(map[string]any{"tokens": tokens})
			}
			p := render.Detect(os.Stdout)
			if len(tokens) == 0 {
				p.Plain("No tokens yet → podaro auth token create --name ci --scope read")
				return nil
			}
			for _, t := range tokens {
				last := "never used"
				if t.LastUsed != nil {
					last = "last used " + t.LastUsed.UTC().Format("2006-01-02 15:04")
				}
				p.Plain(fmt.Sprintf("%-16s pdr_%s…  %-8s created %s · %s", t.Name, t.Prefix, t.Scope, t.Created.UTC().Format("2006-01-02"), last))
			}
			return nil
		},
	}
	revoke := &cobra.Command{
		Use:   "revoke <name>",
		Short: "revoke a token immediately",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := newClient().RevokeToken(context.Background(), args[0]); err != nil {
				return jsonOrErr(err, 1)
			}
			if jsonOut {
				return json.NewEncoder(os.Stdout).Encode(map[string]any{"revoked": args[0]})
			}
			render.Detect(os.Stdout).Check(render.Pass, "token "+args[0]+" revoked", 0, "")
			return nil
		},
	}
	cmd.AddCommand(create, list, revoke)
	return cmd
}

func tildify(path string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return path
	}
	if strings.HasPrefix(path, home) {
		return "~" + strings.TrimPrefix(path, home)
	}
	return path
}
