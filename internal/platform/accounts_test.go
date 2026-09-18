package platform

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// store points a fresh AccountStore at a temporary file.
func store(t *testing.T) AccountStore {
	t.Helper()
	return AccountStore{Path: filepath.Join(t.TempDir(), "accounts.json")}
}

// seedReseller creates one active reseller and fails the test if it cannot.
func seedReseller(t *testing.T, s AccountStore, name string) {
	t.Helper()
	if err := s.Create(Account{Username: name, Role: RoleReseller, State: StateActive}, "correct-horse"); err != nil {
		t.Fatalf("could not create the reseller %q: %v", name, err)
	}
}

func TestAHostThatHasNoAccountFileStartsEmpty(t *testing.T) {
	// The first account has to be creatable on a host where nothing exists yet.
	s := store(t)
	list, err := s.List()
	if err != nil {
		t.Fatalf("an absent file was read as a failure: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("an absent file produced %d accounts", len(list))
	}
}

func TestACorruptAccountFileIsReportedNotIgnored(t *testing.T) {
	s := store(t)
	if err := os.WriteFile(s.Path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.List(); err == nil {
		t.Fatal("a corrupt file was read as an empty store; every account on the host would silently vanish")
	}
}

func TestAPasswordIsNeverReturned(t *testing.T) {
	s := store(t)
	seedReseller(t, s, "bayi")

	list, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if list[0].PasswordHash != "" {
		t.Fatal("List returned a password hash")
	}
	got, ok := s.Get("bayi")
	if !ok || got.PasswordHash != "" {
		t.Fatal("Get returned a password hash")
	}
	auth, ok := s.Authenticate("bayi", "correct-horse")
	if !ok || auth.PasswordHash != "" {
		t.Fatal("Authenticate returned a password hash")
	}
}

func TestThePasswordIsStoredHashedNotAsItCame(t *testing.T) {
	s := store(t)
	seedReseller(t, s, "bayi")
	raw, err := os.ReadFile(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "correct-horse") {
		t.Fatal("the password is on disk in the clear")
	}
	if !strings.Contains(string(raw), "$2a$") {
		t.Fatal("the stored value is not a bcrypt hash")
	}
}

func TestOnlyTheRightPasswordAuthenticates(t *testing.T) {
	s := store(t)
	seedReseller(t, s, "bayi")
	if _, ok := s.Authenticate("bayi", "correct-horse"); !ok {
		t.Fatal("the right password was refused")
	}
	if _, ok := s.Authenticate("bayi", "wrong-horse"); ok {
		t.Fatal("a wrong password was accepted")
	}
	if _, ok := s.Authenticate("nobody", "correct-horse"); ok {
		t.Fatal("an account that does not exist authenticated")
	}
}

func TestASuspendedAccountCannotLogIn(t *testing.T) {
	// Suspension has to stop a login, not only hide a screen.
	s := store(t)
	seedReseller(t, s, "bayi")
	if err := s.Update("bayi", Profile{State: StateSuspended}); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Authenticate("bayi", "correct-horse"); ok {
		t.Fatal("a suspended account logged in with the right password")
	}
}

func TestAUsernameIsMatchedWithoutRegardToCase(t *testing.T) {
	s := store(t)
	seedReseller(t, s, "bayi")
	if _, ok := s.Get("BAYI"); !ok {
		t.Fatal("the same account was not found under a different case")
	}
	if _, ok := s.Authenticate("Bayi", "correct-horse"); !ok {
		t.Fatal("the same account could not log in under a different case")
	}
	if err := s.Create(Account{Username: "BAYI", Role: RoleHosting}, "another-pass"); err == nil {
		t.Fatal("a second account took the same username in a different case")
	}
}

func TestTheAdminUsernameIsReserved(t *testing.T) {
	// The admin identity lives in the agent's own configuration. An admin row
	// here would shadow it and take the recovery path away.
	s := store(t)
	err := s.Create(Account{Username: "admin", Role: RoleReseller}, "correct-horse")
	if err == nil {
		t.Fatal("an account took the reserved name admin")
	}
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("the refusal is not an invalid request: %v", err)
	}
}

func TestOnlyAResellerOrAHostingAccountCanBeStored(t *testing.T) {
	s := store(t)
	for _, role := range []string{"", RoleAdmin, "root", "customer"} {
		if ValidRole(role) {
			t.Fatalf("role %q is writable to this store", role)
		}
		if err := s.Create(Account{Username: "someone", Role: role}, "correct-horse"); err == nil {
			t.Fatalf("an account was created with role %q", role)
		}
	}
}

func TestAUsernameOutsideThePatternIsRefused(t *testing.T) {
	s := store(t)
	for _, name := range []string{"ab", strings.Repeat("a", 33), "has space", "semi;colon", "slash/x", "..", "a$b", "tab\there"} {
		if err := s.Create(Account{Username: name, Role: RoleHosting}, "correct-horse"); err == nil {
			t.Fatalf("username %q was accepted", name)
		}
	}
}

func TestAUsernameIsLowercasedRatherThanRefused(t *testing.T) {
	// Case is normalised, not rejected: an operator typing "Bayi" gets the
	// account they meant, and the case-insensitive lookup then finds it.
	s := store(t)
	if err := s.Create(Account{Username: "Bayi", Role: RoleReseller}, "correct-horse"); err != nil {
		t.Fatalf("a mixed-case username was refused: %v", err)
	}
	got, ok := s.Get("bayi")
	if !ok {
		t.Fatal("the account was not stored under its lowercased name")
	}
	if got.Username != "bayi" {
		t.Fatalf("the stored username is %q, want the lowercased form", got.Username)
	}
}

func TestAShortOrOversizedPasswordIsRefused(t *testing.T) {
	s := store(t)
	for _, password := range []string{"", "short", strings.Repeat("x", maxPasswordLen+1)} {
		if err := s.Create(Account{Username: "bayi", Role: RoleReseller}, password); err == nil {
			t.Fatalf("a password of %d characters was accepted", len(password))
		}
	}
}

func TestANegativeQuotaIsRefused(t *testing.T) {
	s := store(t)
	if err := s.Create(Account{Username: "bayi", Role: RoleReseller, MaxSites: -1}, "correct-horse"); err == nil {
		t.Fatal("a negative site quota was accepted")
	}
	seedReseller(t, s, "bayi2")
	if err := s.Update("bayi2", Profile{State: StateActive, MaxDiskMB: -1}); err == nil {
		t.Fatal("a negative disk quota was accepted")
	}
}

func TestAHostingAccountMustPointAtARealReseller(t *testing.T) {
	s := store(t)
	err := s.Create(Account{Username: "musteri", Role: RoleHosting, Reseller: "nobody"}, "correct-horse")
	if err == nil {
		t.Fatal("a hosting account was created under a reseller that does not exist")
	}
	seedReseller(t, s, "bayi")
	if err := s.Create(Account{Username: "musteri", Role: RoleHosting, Reseller: "bayi"}, "correct-horse"); err != nil {
		t.Fatalf("a hosting account under a real reseller was refused: %v", err)
	}
}

func TestAHostingAccountMayAlsoSitDirectlyUnderTheAdmin(t *testing.T) {
	s := store(t)
	if err := s.Create(Account{Username: "musteri", Role: RoleHosting}, "correct-horse"); err != nil {
		t.Fatalf("a hosting account with no reseller was refused: %v", err)
	}
}

func TestAHostingAccountCannotPointAtAnotherHostingAccount(t *testing.T) {
	s := store(t)
	if err := s.Create(Account{Username: "birinci", Role: RoleHosting}, "correct-horse"); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(Account{Username: "ikinci", Role: RoleHosting, Reseller: "birinci"}, "correct-horse"); err == nil {
		t.Fatal("a hosting account was placed under another hosting account")
	}
}

func TestAResellerStillHoldingAHostingAccountIsNotDeleted(t *testing.T) {
	// Deleting it would leave those accounts pointing at a reseller that no
	// longer exists: an ownership chain with a hole in it.
	s := store(t)
	seedReseller(t, s, "bayi")
	if err := s.Create(Account{Username: "musteri", Role: RoleHosting, Reseller: "bayi"}, "correct-horse"); err != nil {
		t.Fatal(err)
	}
	err := s.Delete("bayi")
	if err == nil {
		t.Fatal("a reseller was deleted while it still held a hosting account")
	}
	if !strings.Contains(err.Error(), "musteri") {
		t.Fatalf("the refusal does not name the account holding it back: %v", err)
	}
	if err := s.Delete("musteri"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete("bayi"); err != nil {
		t.Fatalf("the reseller was still refused after its last account went: %v", err)
	}
}

func TestDeletingAnAccountThatIsNotThereIsReportedAsNotFound(t *testing.T) {
	s := store(t)
	if err := s.Delete("nobody"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleting an absent account answered %v", err)
	}
	if err := s.Update("nobody", Profile{State: StateActive}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("updating an absent account answered %v", err)
	}
	if err := s.SetPassword("nobody", "correct-horse"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("setting an absent account's password answered %v", err)
	}
}

func TestANewPasswordReplacesTheOldOne(t *testing.T) {
	s := store(t)
	seedReseller(t, s, "bayi")
	if err := s.SetPassword("bayi", "a-new-password"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Authenticate("bayi", "correct-horse"); ok {
		t.Fatal("the old password still works")
	}
	if _, ok := s.Authenticate("bayi", "a-new-password"); !ok {
		t.Fatal("the new password does not work")
	}
}

func TestUpdateLeavesThePasswordAlone(t *testing.T) {
	s := store(t)
	seedReseller(t, s, "bayi")
	if err := s.Update("bayi", Profile{State: StateActive, FullName: "Bir Bayi", Email: "a@b.c", MaxSites: 10}); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Authenticate("bayi", "correct-horse"); !ok {
		t.Fatal("updating the profile broke the password")
	}
	got, _ := s.Get("bayi")
	if got.FullName != "Bir Bayi" || got.MaxSites != 10 {
		t.Fatalf("the profile did not change: %+v", got)
	}
}

func TestAHalfWrittenFileNeverReplacesTheGoodOne(t *testing.T) {
	// The file is written beside itself and renamed over, so a failure leaves
	// the previous content intact rather than an unreadable store.
	s := store(t)
	seedReseller(t, s, "bayi")
	if _, err := os.Stat(s.Path + ".new"); err == nil {
		t.Fatal("the temporary file was left behind")
	}
	if err := s.Create(Account{Username: "musteri", Role: RoleHosting}, "correct-horse"); err != nil {
		t.Fatal(err)
	}
	list, err := s.List()
	if err != nil || len(list) != 2 {
		t.Fatalf("the store holds %d accounts after two creates (%v)", len(list), err)
	}
}
