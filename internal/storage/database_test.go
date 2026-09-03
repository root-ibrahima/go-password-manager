package storage

import (
	"database/sql"
	"os"
	"testing"
)

// openTestDB initialise un coffre isolé et renvoie la base ouverte.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	chdirTemp(t)

	dek, err := InitVault("mot-de-passe-maître")
	if err != nil {
		t.Fatalf("InitVault() a échoué : %v", err)
	}
	dbKey, err := DBKey(dek)
	if err != nil {
		t.Fatalf("DBKey() a échoué : %v", err)
	}
	db, err := InitDB(dbKey)
	if err != nil {
		t.Fatalf("InitDB() a échoué : %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestInitDBRejectsBadKeyLength(t *testing.T) {
	chdirTemp(t)

	if _, err := InitDB([]byte("clé trop courte")); err == nil {
		t.Fatal("InitDB() aurait dû refuser une clé de mauvaise taille")
	}
}

func TestDatabaseFilePermissions(t *testing.T) {
	openTestDB(t)

	info, err := os.Stat(DBFile)
	if err != nil {
		t.Fatalf("stat de %s : %v", DBFile, err)
	}
	// La base est aussi sensible que le fichier de clé : elle ne doit pas être
	// lisible par les autres utilisateurs de la machine.
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("permissions de %s = %04o, attendu 0600", DBFile, perm)
	}
}

func TestDatabaseIsEncryptedOnDisk(t *testing.T) {
	db := openTestDB(t)

	if err := AddEntry(db, "exemple-unique.test", "alice", "chiffré"); err != nil {
		t.Fatalf("AddEntry() a échoué : %v", err)
	}

	raw, err := os.ReadFile(DBFile)
	if err != nil {
		t.Fatalf("lecture de %s : %v", DBFile, err)
	}

	// SQLCipher doit chiffrer jusqu'à l'en-tête : ni le nom du site, ni la
	// signature SQLite en clair ne doivent apparaître.
	if string(raw[:6]) == "SQLite" {
		t.Fatal("en-tête SQLite en clair : la base n'est pas chiffrée")
	}
	for _, needle := range []string{"exemple-unique.test", "alice"} {
		if containsBytes(raw, needle) {
			t.Fatalf("%q apparaît en clair dans le fichier de base", needle)
		}
	}
}

func containsBytes(haystack []byte, needle string) bool {
	n := []byte(needle)
	for i := 0; i+len(n) <= len(haystack); i++ {
		match := true
		for j := range n {
			if haystack[i+j] != n[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func TestAddListDeleteEntry(t *testing.T) {
	db := openTestDB(t)

	if err := AddEntry(db, "github.com", "alice", "chiffré-1"); err != nil {
		t.Fatalf("AddEntry() a échoué : %v", err)
	}
	if err := AddEntry(db, "stripe.com", "bob", "chiffré-2"); err != nil {
		t.Fatalf("AddEntry() a échoué : %v", err)
	}

	entries, err := ListEntries(db)
	if err != nil {
		t.Fatalf("ListEntries() a échoué : %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("%d entrées, attendu 2", len(entries))
	}
	// ORDER BY site : github vient avant stripe.
	if entries[0].Site != "github.com" {
		t.Fatalf("première entrée = %q, attendu github.com", entries[0].Site)
	}
	if entries[0].Password != "chiffré-1" {
		t.Fatal("le mot de passe stocké a été altéré")
	}

	if err := DeleteEntry(db, entries[0].ID); err != nil {
		t.Fatalf("DeleteEntry() a échoué : %v", err)
	}

	remaining, err := ListEntries(db)
	if err != nil {
		t.Fatalf("ListEntries() a échoué : %v", err)
	}
	if len(remaining) != 1 || remaining[0].Site != "stripe.com" {
		t.Fatalf("après suppression : %+v", remaining)
	}
}

func TestDeleteEntryUnknownID(t *testing.T) {
	db := openTestDB(t)

	// Ne doit pas faire croire à une suppression réussie.
	if err := DeleteEntry(db, 4242); err == nil {
		t.Fatal("DeleteEntry() aurait dû signaler l'absence de l'entrée")
	}
}

func TestListEntriesEmpty(t *testing.T) {
	db := openTestDB(t)

	entries, err := ListEntries(db)
	if err != nil {
		t.Fatalf("ListEntries() a échoué : %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("%d entrées sur une base vide", len(entries))
	}
}

func TestWrongKeyCannotOpenDatabase(t *testing.T) {
	chdirTemp(t)

	dek, err := InitVault("mot-de-passe-maître")
	if err != nil {
		t.Fatalf("InitVault() a échoué : %v", err)
	}
	dbKey, _ := DBKey(dek)
	db, err := InitDB(dbKey)
	if err != nil {
		t.Fatalf("InitDB() a échoué : %v", err)
	}
	if err := AddEntry(db, "site.test", "alice", "chiffré"); err != nil {
		t.Fatalf("AddEntry() a échoué : %v", err)
	}
	_ = db.Close()

	// Une autre clé ne doit pas permettre de lire la base existante.
	otherDEK, _ := InitVault("autre-mot-de-passe")
	otherKey, _ := DBKey(otherDEK)

	otherDB, err := InitDB(otherKey)
	if err == nil {
		_, err = ListEntries(otherDB)
		_ = otherDB.Close()
	}
	if err == nil {
		t.Fatal("la base a été lue avec une clé incorrecte")
	}
}
