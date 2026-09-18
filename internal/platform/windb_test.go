package platform

import (
	"strings"
	"testing"
)

func TestOnlyAnAllowlistedIdentifierReachesTheSQL(t *testing.T) {
	// The SQL is built by concatenation, so this pattern is the primary defense
	// rather than a convenience.
	for _, name := range []string{
		"", "1leading", "-dash", "has space", "quote'x", "bracket]x", "semi;colon",
		"dash-name", "dot.name", "back\\slash", "star*", "line\nbreak", strings.Repeat("a", 65),
		"master--", "x'; DROP DATABASE [master]; --",
	} {
		if err := validateDBName("database name", name); err == nil {
			t.Fatalf("identifier %q was accepted into SQL text", name)
		}
	}
	for _, name := range []string{"shop", "_internal", "Shop_2026", strings.Repeat("a", 64)} {
		if err := validateDBName("database name", name); err != nil {
			t.Fatalf("identifier %q was refused: %v", name, err)
		}
	}
}

func TestAPasswordSqlcmdWouldReadAsACommandIsRefused(t *testing.T) {
	// sqlcmd processes the text of -Q line by line BEFORE the server sees it: a
	// bare "GO" line is a batch separator, a line starting with ":" is a sqlcmd
	// command, and "$(...)" is a variable substitution. sqlcmd does not know it
	// is inside a string literal.
	for _, password := range []string{
		"", "pass\nGO\nDROP DATABASE master", "pass\r\n:!! calc.exe", "pass$(Env:PATH)",
	} {
		if err := validateDBPassword(password); err == nil {
			t.Fatalf("password %q was accepted", password)
		}
	}
	if err := validateDBPassword("Str0ng!Pass-word"); err != nil {
		t.Fatalf("an ordinary password was refused: %v", err)
	}
}

func TestAQuoteInAPasswordIsDoubledForTheServer(t *testing.T) {
	// A quote is allowed through the character gate, so the literal escape is
	// what has to hold.
	first, _ := createStatements("shop", "shopuser", "pa'ss")
	if !strings.Contains(first, "N'pa''ss'") {
		t.Fatalf("the quote was not doubled in the literal:\n%s", first)
	}
	if strings.Contains(first, "N'pa'ss'") {
		t.Fatal("an unescaped quote reached the statement, which would end the literal early")
	}
}

func TestABracketIsDoubledInsideAnIdentifier(t *testing.T) {
	// The pattern already refuses a bracket, so this is the second layer.
	if got := escapeBrackets("a]b"); got != "a]]b" {
		t.Fatalf("escapeBrackets gave %q", got)
	}
	if got := escapeLiteral("a'b"); got != "a''b" {
		t.Fatalf("escapeLiteral gave %q", got)
	}
}

func TestASystemDatabaseIsNeverDroppable(t *testing.T) {
	cases := map[string][]string{
		"mssql": {"master", "tempdb", "model", "msdb", "MASTER", "MsDb"},
		"mysql": {"information_schema", "mysql", "performance_schema", "sys"},
		"pgsql": {"postgres", "template0", "template1"},
	}
	for engine, names := range cases {
		for _, name := range names {
			if !isSystemDatabase(engine, name) {
				t.Errorf("%s/%s is not protected", engine, name)
			}
		}
	}
	if isSystemDatabase("mssql", "shop") {
		t.Fatal("an ordinary database was treated as a system one")
	}
	if isSystemDatabase("mssql", "postgres") {
		t.Fatal("another engine's system database was protected on mssql, which would block a real name")
	}
}

func TestOnlyTheThreeKnownEnginesAreAccepted(t *testing.T) {
	for _, engine := range []string{"", "sqlite", "oracle", "MSSQL", "mssql;x"} {
		if validEngine(engine) {
			t.Fatalf("engine %q was accepted", engine)
		}
	}
	for _, engine := range []string{"mssql", "mysql", "pgsql"} {
		if !validEngine(engine) {
			t.Fatalf("engine %q was refused", engine)
		}
	}
}

func TestCreationIsSplitIntoTwoBatches(t *testing.T) {
	// CREATE DATABASE and USE cannot share a batch: SQL Server cannot connect to
	// the new database until the creating batch closes and answers Msg 911.
	first, second := createStatements("shop", "shopuser", "pw")
	if !strings.Contains(first, "CREATE DATABASE") {
		t.Fatal("the first batch does not create the database")
	}
	if strings.Contains(first, "CREATE USER") {
		t.Fatal("the user is created in the same batch as the database; SQL Server answers Msg 911")
	}
	if !strings.Contains(second, "CREATE USER") || !strings.Contains(second, "db_owner") {
		t.Fatalf("the second batch does not create the user and grant its role:\n%s", second)
	}
}

func TestEveryCreationStatementIsIdempotent(t *testing.T) {
	// If the agent dies between the two calls and the request is retried, the
	// second attempt must not fail on "already exists": a half-built state has
	// to be recoverable.
	first, second := createStatements("shop", "shopuser", "pw")
	if !strings.Contains(first, "IF DB_ID(N'shop') IS NULL CREATE DATABASE") {
		t.Fatalf("CREATE DATABASE is unguarded:\n%s", first)
	}
	if !strings.Contains(first, "IF NOT EXISTS") {
		t.Fatalf("CREATE LOGIN is unguarded:\n%s", first)
	}
	if strings.Count(second, "IF NOT EXISTS") != 2 {
		t.Fatalf("the user or the role grant is unguarded:\n%s", second)
	}
}

func TestAnExistingLoginHasItsPasswordReapplied(t *testing.T) {
	// Leaving the old password would keep it while the panel shows a new one,
	// and the site could never connect.
	first, _ := createStatements("shop", "shopuser", "newpass")
	if !strings.Contains(first, "ALTER LOGIN [shopuser] WITH PASSWORD = N'newpass'") {
		t.Fatalf("an existing login keeps its old password:\n%s", first)
	}
}

func TestTheDropClearsBlockingConnections(t *testing.T) {
	// Without this an open connection holds the drop off indefinitely.
	got := dropStatement("shop")
	if !strings.Contains(got, "SET SINGLE_USER WITH ROLLBACK IMMEDIATE") {
		t.Fatalf("the drop does not clear open connections:\n%s", got)
	}
	if !strings.Contains(got, "DROP DATABASE [shop]") {
		t.Fatalf("the drop does not drop:\n%s", got)
	}
}

func TestAFailedDropCanBeReopened(t *testing.T) {
	// A drop that stops part way leaves the database in single-user mode, where
	// the customer cannot reach it at all.
	got := reopenStatement("shop")
	if !strings.Contains(got, "SET MULTI_USER") {
		t.Fatalf("there is no way back from single-user mode:\n%s", got)
	}
	if !strings.Contains(got, "IF DB_ID(N'shop') IS NOT NULL") {
		t.Fatalf("reopening is unguarded and would error when the database did drop:\n%s", got)
	}
}

func TestAnOrphanLoginIsOnlyDroppedWhenNothingMapsIt(t *testing.T) {
	// Failing safe matters more than tidiness: another site may be using it.
	got := orphanLoginStatement("shopuser")
	if !strings.Contains(got, "IF @used = 0 DROP LOGIN [shopuser]") {
		t.Fatalf("the login is dropped without checking whether it is in use:\n%s", got)
	}
	if !strings.Contains(got, "BEGIN CATCH SET @used = 1; END CATCH") {
		t.Fatalf("a failed scan does not keep the login:\n%s", got)
	}
	if !strings.Contains(got, "database_id > 4") {
		t.Fatalf("the scan does not limit itself to user databases:\n%s", got)
	}
}

func TestADatabaseNameWithTheSeparatorInItSurvivesParsing(t *testing.T) {
	// The size is always a number and always last, so the split is at the LAST
	// separator. Splitting at the first would cut a name containing one.
	rows := parseRows("my|shop|42\n", "|")
	if len(rows) != 1 || rows[0].Name != "my|shop" || rows[0].SizeMB != 42 {
		t.Fatalf("the row read as %+v", rows)
	}
}

func TestALineThatIsNotARowIsSkipped(t *testing.T) {
	out := "Warning: something happened\nshop|100\n\nChanged database context.\n"
	rows := parseRows(out, "|")
	if len(rows) != 1 || rows[0].Name != "shop" {
		t.Fatalf("banner lines were not skipped: %+v", rows)
	}
}

func TestATabSeparatedListingIsReadTheSameWay(t *testing.T) {
	rows := parseRows("shop\t100\nblog\t0\n", "\t")
	if len(rows) != 2 || rows[1].SizeMB != 0 {
		t.Fatalf("the tab listing read as %+v", rows)
	}
}

func TestAnEmptyListingIsAnEmptySlice(t *testing.T) {
	if rows := parseRows("", "|"); len(rows) != 0 {
		t.Fatalf("an empty listing produced %+v", rows)
	}
}

func TestOnlyLoginNamesThisAgentCouldHaveMadeAreCleanedUp(t *testing.T) {
	// A name outside the pattern is not one this agent created, and dropping it
	// would remove someone else's login.
	names := loginNames("shopuser\r\nNT AUTHORITY\\SYSTEM\r\n\r\nblog_user\r\n")
	if len(names) != 2 || names[0] != "shopuser" || names[1] != "blog_user" {
		t.Fatalf("the login list read as %v", names)
	}
}
