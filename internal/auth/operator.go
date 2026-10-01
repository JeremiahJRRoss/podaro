// SPDX-License-Identifier: AGPL-3.0-only

// Package auth is the engine's identity layer (API §2; plan S5): the one
// operator account (Argon2id at rest in auth.json), console sessions
// (server-side records signed into a domain cookie), scoped bearer
// tokens (hashed at rest), and the per-source login throttle with its
// audited lockout. The local socket needs none of this — possession of
// the operating-system user account is the credential there.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/jeremiahjrross/podaro/internal/fsx"
)

// Argon2id parameters (INSTALL §2 step 5: 64 MiB, 3 iterations).
const (
	argonMemoryKiB = 64 * 1024
	argonTime      = 3
	argonThreads   = 1
	argonKeyLen    = 32
	saltLen        = 16
	sessionKeyLen  = 32
)

// ErrNoOperator reports that auth setup has not run.
var ErrNoOperator = errors.New("no operator account")

// Operator is the one full account (API §2.1).
type Operator struct {
	Username string
	Created  time.Time

	salt, hash, sessionKey []byte
	memory, iterations     uint32
	threads                uint8
}

type operatorFile struct {
	Username   string     `json:"username"`
	Argon2id   argonParam `json:"argon2id"`
	SessionKey string     `json:"session_key"`
	Created    time.Time  `json:"created"`
}

type argonParam struct {
	Salt    string `json:"salt"`
	Hash    string `json:"hash"`
	Memory  uint32 `json:"memory_kib"`
	Time    uint32 `json:"iterations"`
	Threads uint8  `json:"threads"`
}

// NewOperator hashes the password and generates a fresh session-signing
// key. It does not check the password policy — CheckPassword does, and
// callers run it first so the error reaches the operator unhashed.
func NewOperator(username, password string, now time.Time) (*Operator, error) {
	salt, err := randomBytes(saltLen)
	if err != nil {
		return nil, err
	}
	key, err := randomBytes(sessionKeyLen)
	if err != nil {
		return nil, err
	}
	o := &Operator{Username: username, Created: now.UTC(), salt: salt, sessionKey: key,
		memory: argonMemoryKiB, iterations: argonTime, threads: argonThreads}
	o.hash = argon2.IDKey([]byte(password), salt, o.iterations, o.memory, o.threads, argonKeyLen)
	return o, nil
}

// LoadOperator reads auth.json; ErrNoOperator when it does not exist.
func LoadOperator(path string) (*Operator, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoOperator
	}
	if err != nil {
		return nil, err
	}
	var f operatorFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	o := &Operator{Username: f.Username, Created: f.Created, memory: f.Argon2id.Memory, iterations: f.Argon2id.Time, threads: f.Argon2id.Threads}
	if o.salt, err = base64.StdEncoding.DecodeString(f.Argon2id.Salt); err != nil {
		return nil, fmt.Errorf("%s: salt: %w", path, err)
	}
	if o.hash, err = base64.StdEncoding.DecodeString(f.Argon2id.Hash); err != nil {
		return nil, fmt.Errorf("%s: hash: %w", path, err)
	}
	if o.sessionKey, err = base64.StdEncoding.DecodeString(f.SessionKey); err != nil {
		return nil, fmt.Errorf("%s: session key: %w", path, err)
	}
	if o.Username == "" || len(o.hash) == 0 || len(o.sessionKey) < 16 || o.memory == 0 || o.iterations == 0 || o.threads == 0 {
		return nil, fmt.Errorf("%s: incomplete operator record", path)
	}
	return o, nil
}

// Save writes auth.json atomically at mode 0600 (INSTALL §3).
func (o *Operator) Save(path string) error {
	tmp, err := o.SaveTemp(path)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return fsx.SyncDir(filepath.Dir(path))
}

// SaveTemp writes the record to a temporary file of its own beside path
// (mode 0600) and returns its name: the caller moves it into place once
// the act is audited, or removes it. Two replacements never share a
// file, so what a caller moves into place is the record it audited.
func (o *Operator) SaveTemp(path string) (string, error) {
	f := operatorFile{
		Username: o.Username, Created: o.Created,
		Argon2id: argonParam{Salt: base64.StdEncoding.EncodeToString(o.salt), Hash: base64.StdEncoding.EncodeToString(o.hash),
			Memory: o.memory, Time: o.iterations, Threads: o.threads},
		SessionKey: base64.StdEncoding.EncodeToString(o.sessionKey),
	}
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	file, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return "", err
	}
	tmp := file.Name()
	if _, err := file.Write(append(raw, '\n')); err != nil {
		file.Close()
		os.Remove(tmp)
		return "", err
	}
	if err := fsx.Sync(file); err != nil { // durable before the rename that makes it the record
		file.Close()
		os.Remove(tmp)
		return "", err
	}
	if err := file.Close(); err != nil {
		os.Remove(tmp)
		return "", err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		os.Remove(tmp)
		return "", err
	}
	return tmp, nil
}

// Verify reports whether the password matches, in constant time over the
// hash comparison.
func (o *Operator) Verify(password string) bool {
	got := argon2.IDKey([]byte(password), o.salt, o.iterations, o.memory, o.threads, uint32(len(o.hash)))
	return subtle.ConstantTimeCompare(got, o.hash) == 1
}

// SessionKey is the cookie-signing key.
func (o *Operator) SessionKey() []byte { return o.sessionKey }

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
