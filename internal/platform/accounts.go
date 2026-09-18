package platform

// Accounts for the Windows agent's own local panel: reseller and hosting.
//
// This is the Windows counterpart of the panel's users table, and it is NOT the
// same store. The panel runs on Linux against MariaDB; a Windows host has
// neither, so the agent keeps its accounts in one JSON file.
//
// THE ADMIN IS NOT IN HERE. The agent's admin identity lives in the agent's own
// configuration, so the password-recovery path on the command line keeps working
// and an operator cannot lock themselves out by corrupting this file. This store
// holds resellers and hosting accounts only.
//
// The path is a field rather than a package variable, so a test can point it at
// a temporary directory without reaching into package state, and the agent names
// the real location once.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// Roles. The admin role is named here because sessions and scope checks need
// the constant, even though no admin row is ever stored.
const (
	RoleAdmin    = "admin"
	RoleReseller = "reseller"
	RoleHosting  = "hosting"
)

// Account states.
const (
	StateActive    = "active"
	StateSuspended = "suspended"
)

const (
	minPasswordLen = 8
	maxPasswordLen = 200
)

// usernamePattern is what an account name may contain: 3 to 32 lowercase
// letters, digits, dot, underscore or hyphen.
var usernamePattern = regexp.MustCompile(`^[a-z0-9._-]{3,32}$`)

// ErrNotFound is returned when no account carries the given username.
var ErrNotFound = errors.New("account not found")

// Account is one reseller or hosting account.
//
// PasswordHash is written to disk in full and STRIPPED from everything this
// package returns, so a handler cannot leak it into an answer by forgetting to.
type Account struct {
	Username     string `json:"username"`
	PasswordHash string `json:"passwordHash,omitempty"`
	Role         string `json:"role"`     // reseller | hosting
	Reseller     string `json:"reseller"` // the reseller a hosting account sits under; empty means directly under the admin
	State        string `json:"state"`    // active | suspended
	FullName     string `json:"fullName"`
	Email        string `json:"email"`
	MaxSites     int    `json:"maxSites"`  // reseller quota, 0 is unlimited
	MaxDiskMB    int64  `json:"maxDiskMB"` // reseller quota, 0 is unlimited
	Oversell     bool   `json:"oversell"`  // may a reseller sell more than it holds
	CreatedAt    string `json:"createdAt"`
}

// AccountStore is the JSON file holding the accounts.
type AccountStore struct{ Path string }

// accountFile is the file's shape.
type accountFile struct {
	Accounts []Account `json:"accounts"`
}

// ValidRole reports whether a role may be WRITTEN to this store. The admin role
// is deliberately absent: it lives in the agent's configuration.
func ValidRole(role string) bool { return role == RoleReseller || role == RoleHosting }

// normalizeUsername lowercases and trims a username so lookups and writes agree.
func normalizeUsername(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// validateUsername refuses a name this store will not carry.
func validateUsername(name string) error {
	if name == RoleAdmin {
		return fmt.Errorf("%q is reserved: %w", RoleAdmin, ErrInvalidRequest)
	}
	if !usernamePattern.MatchString(name) {
		return fmt.Errorf("a username is 3 to 32 characters of a-z, 0-9, dot, underscore or hyphen: %w", ErrInvalidRequest)
	}
	return nil
}

// validatePassword refuses a password this store will not hash.
func validatePassword(password string) error {
	if len(password) < minPasswordLen || len(password) > maxPasswordLen {
		return fmt.Errorf("a password is %d to %d characters: %w", minPasswordLen, maxPasswordLen, ErrInvalidRequest)
	}
	return nil
}

// read loads the file. A missing or empty file is an empty store, not a failure:
// the first account has to be creatable on a host where nothing exists yet.
func (s AccountStore) read() (accountFile, error) {
	file := accountFile{Accounts: []Account{}}
	b, err := os.ReadFile(s.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return file, nil
		}
		return file, err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return file, nil
	}
	if err := json.Unmarshal(b, &file); err != nil {
		return file, fmt.Errorf("the account file is corrupt: %w", err)
	}
	if file.Accounts == nil {
		file.Accounts = []Account{}
	}
	return file, nil
}

// write replaces the file atomically. A partial write would leave every account
// on the host unreadable, so the new content is written beside the file and
// renamed over it.
func (s AccountStore) write(file accountFile) error {
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	temp := s.Path + ".new"
	if err := os.WriteFile(temp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(temp, s.Path)
}

// indexOf finds an account by username, comparing case-insensitively.
func indexOf(file accountFile, username string) int {
	return slices.IndexFunc(file.Accounts, func(a Account) bool {
		return strings.EqualFold(a.Username, username)
	})
}

// stripped returns a copy with no password hash in it.
func stripped(a Account) Account {
	a.PasswordHash = ""
	return a
}

// List returns every account, with no password hash.
func (s AccountStore) List() ([]Account, error) {
	file, err := s.read()
	if err != nil {
		return nil, err
	}
	out := make([]Account, len(file.Accounts))
	for i, a := range file.Accounts {
		out[i] = stripped(a)
	}
	return out, nil
}

// Get returns one account, with no password hash.
func (s AccountStore) Get(username string) (Account, bool) {
	file, err := s.read()
	if err != nil {
		return Account{}, false
	}
	i := indexOf(file, normalizeUsername(username))
	if i < 0 {
		return Account{}, false
	}
	return stripped(file.Accounts[i]), true
}

// Authenticate checks a username and password.
//
// A suspended account fails here, not later: suspension has to stop a login, not
// only hide a screen. The admin is NOT checked here; the caller tries the
// agent's own admin identity first.
func (s AccountStore) Authenticate(username, password string) (Account, bool) {
	file, err := s.read()
	if err != nil {
		return Account{}, false
	}
	i := indexOf(file, normalizeUsername(username))
	if i < 0 {
		// The password is still compared against a dummy hash so a missing
		// account costs the same time as a wrong password. Without it the
		// response time says which usernames exist.
		_ = bcrypt.CompareHashAndPassword([]byte(dummyHash), []byte(password))
		return Account{}, false
	}
	account := file.Accounts[i]
	if account.State != StateActive {
		return Account{}, false
	}
	if bcrypt.CompareHashAndPassword([]byte(account.PasswordHash), []byte(password)) != nil {
		return Account{}, false
	}
	return stripped(account), true
}

// dummyHash is a valid bcrypt hash of a value nobody knows. It exists only to
// give the "no such account" path the same cost as a real comparison.
const dummyHash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"

// checkNewAccount validates everything about a new account except its password.
func checkNewAccount(file accountFile, a Account) error {
	if err := validateUsername(a.Username); err != nil {
		return err
	}
	if !ValidRole(a.Role) {
		return fmt.Errorf("role %q is not reseller or hosting: %w", a.Role, ErrInvalidRequest)
	}
	if a.MaxSites < 0 || a.MaxDiskMB < 0 {
		return fmt.Errorf("a quota cannot be negative: %w", ErrInvalidRequest)
	}
	if indexOf(file, a.Username) >= 0 {
		return fmt.Errorf("the username %q is taken: %w", a.Username, ErrInvalidRequest)
	}
	if a.Role != RoleHosting || a.Reseller == "" {
		return nil
	}
	i := indexOf(file, normalizeUsername(a.Reseller))
	if i < 0 || file.Accounts[i].Role != RoleReseller {
		return fmt.Errorf("%q is not an existing reseller: %w", a.Reseller, ErrInvalidRequest)
	}
	return nil
}

// Create adds a reseller or hosting account. The password arrives in the clear
// and is hashed here; it is never stored as it came.
func (s AccountStore) Create(a Account, password string) error {
	a.Username = normalizeUsername(a.Username)
	if err := validatePassword(password); err != nil {
		return err
	}
	file, err := s.read()
	if err != nil {
		return err
	}
	if err := checkNewAccount(file, a); err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("could not hash the password: %w", err)
	}
	a.PasswordHash = string(hash)
	if a.State == "" {
		a.State = StateActive
	}
	file.Accounts = append(file.Accounts, a)
	return s.write(file)
}

// Profile is what Update may change. The role and the password are deliberately
// not in it: changing a role moves an account between scopes and changing a
// password goes through SetPassword, which hashes.
type Profile struct {
	FullName  string
	Email     string
	State     string
	MaxSites  int
	MaxDiskMB int64
	Oversell  bool
}

// Update changes one account's profile and quota.
func (s AccountStore) Update(username string, p Profile) error {
	if p.State != StateActive && p.State != StateSuspended {
		return fmt.Errorf("state %q is not active or suspended: %w", p.State, ErrInvalidRequest)
	}
	if p.MaxSites < 0 || p.MaxDiskMB < 0 {
		return fmt.Errorf("a quota cannot be negative: %w", ErrInvalidRequest)
	}
	file, err := s.read()
	if err != nil {
		return err
	}
	i := indexOf(file, normalizeUsername(username))
	if i < 0 {
		return fmt.Errorf("%q: %w", username, ErrNotFound)
	}
	file.Accounts[i].FullName = p.FullName
	file.Accounts[i].Email = p.Email
	file.Accounts[i].State = p.State
	file.Accounts[i].MaxSites = p.MaxSites
	file.Accounts[i].MaxDiskMB = p.MaxDiskMB
	file.Accounts[i].Oversell = p.Oversell
	return s.write(file)
}

// SetPassword replaces one account's password.
func (s AccountStore) SetPassword(username, password string) error {
	if err := validatePassword(password); err != nil {
		return err
	}
	file, err := s.read()
	if err != nil {
		return err
	}
	i := indexOf(file, normalizeUsername(username))
	if i < 0 {
		return fmt.Errorf("%q: %w", username, ErrNotFound)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("could not hash the password: %w", err)
	}
	file.Accounts[i].PasswordHash = string(hash)
	return s.write(file)
}

// Delete removes an account.
//
// A reseller that still has hosting accounts under it is REFUSED. Deleting it
// would leave those accounts pointing at a reseller that no longer exists, which
// is an ownership chain with a hole in it.
func (s AccountStore) Delete(username string) error {
	username = normalizeUsername(username)
	file, err := s.read()
	if err != nil {
		return err
	}
	i := indexOf(file, username)
	if i < 0 {
		return fmt.Errorf("%q: %w", username, ErrNotFound)
	}
	if file.Accounts[i].Role == RoleReseller {
		if held := heldBy(file, username); held != "" {
			return fmt.Errorf("the reseller still holds the hosting account %s; move or remove it first: %w", held, ErrInvalidRequest)
		}
	}
	file.Accounts = slices.Delete(file.Accounts, i, i+1)
	return s.write(file)
}

// heldBy names one hosting account sitting under a reseller, or "" for none.
func heldBy(file accountFile, reseller string) string {
	for _, a := range file.Accounts {
		if a.Role == RoleHosting && strings.EqualFold(a.Reseller, reseller) {
			return a.Username
		}
	}
	return ""
}
