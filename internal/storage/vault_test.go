package storage

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

// chdirTemp isole chaque test dans son propre répertoire : vault.key et
// passwords.db sont créés avec des chemins relatifs.
func chdirTemp(t *testing.T) {
	t.Helper()
	t.Chdir(t.TempDir())
}

func TestInitVaultThenUnlock(t *testing.T) {
	chdirTemp(t)

	dek, err := InitVault("mot-de-passe-maître")
	if err != nil {
		t.Fatalf("InitVault() a échoué : %v", err)
	}
	if len(dek) == 0 {
		t.Fatal("InitVault() a renvoyé une clé vide")
	}

	unlocked, err := UnlockVault("mot-de-passe-maître")
	if err != nil {
		t.Fatalf("UnlockVault() a échoué : %v", err)
	}
	if !bytes.Equal(dek, unlocked) {
		t.Fatal("la clé déverrouillée diffère de celle créée")
	}
}

func TestUnlockVaultWrongPassword(t *testing.T) {
	chdirTemp(t)

	if _, err := InitVault("le-bon"); err != nil {
		t.Fatalf("InitVault() a échoué : %v", err)
	}

	if _, err := UnlockVault("le-mauvais"); err == nil {
		t.Fatal("UnlockVault() aurait dû refuser un mauvais mot de passe")
	}
}

func TestUnlockVaultNotInitialised(t *testing.T) {
	chdirTemp(t)

	_, err := UnlockVault("peu importe")
	if !errors.Is(err, ErrVaultNotInitialised) {
		t.Fatalf("erreur = %v, attendu ErrVaultNotInitialised", err)
	}
}

func TestVaultKeyFileContainsNoPlaintextKey(t *testing.T) {
	chdirTemp(t)

	dek, err := InitVault("mot-de-passe-maître")
	if err != nil {
		t.Fatalf("InitVault() a échoué : %v", err)
	}

	raw, err := os.ReadFile(VaultKeyFile)
	if err != nil {
		t.Fatalf("lecture de %s : %v", VaultKeyFile, err)
	}

	// Ni la clé de données, ni le mot de passe maître ne doivent apparaître.
	if bytes.Contains(raw, dek) {
		t.Fatal("la clé de données est écrite en clair dans le fichier de clé")
	}
	if strings.Contains(string(raw), "mot-de-passe-maître") {
		t.Fatal("le mot de passe maître apparaît dans le fichier de clé")
	}

	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("le fichier de clé n'est pas du JSON valide : %v", err)
	}
	if parsed["kdf"] != "argon2id" {
		t.Fatalf("kdf = %v, attendu argon2id", parsed["kdf"])
	}
}

func TestVaultKeyFilePermissions(t *testing.T) {
	chdirTemp(t)

	if _, err := InitVault("mot-de-passe-maître"); err != nil {
		t.Fatalf("InitVault() a échoué : %v", err)
	}

	info, err := os.Stat(VaultKeyFile)
	if err != nil {
		t.Fatalf("stat de %s : %v", VaultKeyFile, err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("permissions de %s = %04o, attendu 0600", VaultKeyFile, perm)
	}
}

func TestChangeMasterPasswordKeepsDataKey(t *testing.T) {
	chdirTemp(t)

	original, err := InitVault("ancien")
	if err != nil {
		t.Fatalf("InitVault() a échoué : %v", err)
	}

	if err := ChangeMasterPassword("ancien", "nouveau"); err != nil {
		t.Fatalf("ChangeMasterPassword() a échoué : %v", err)
	}

	// Le point clé de l'enveloppement : la clé de données ne change pas, donc
	// les entrées déjà chiffrées restent lisibles sans re-chiffrement.
	afterChange, err := UnlockVault("nouveau")
	if err != nil {
		t.Fatalf("UnlockVault() avec le nouveau mot de passe : %v", err)
	}
	if !bytes.Equal(original, afterChange) {
		t.Fatal("la clé de données a changé : les entrées existantes deviendraient illisibles")
	}

	if _, err := UnlockVault("ancien"); err == nil {
		t.Fatal("l'ancien mot de passe fonctionne encore après changement")
	}
}

func TestChangeMasterPasswordRejectsWrongCurrent(t *testing.T) {
	chdirTemp(t)

	if _, err := InitVault("ancien"); err != nil {
		t.Fatalf("InitVault() a échoué : %v", err)
	}

	if err := ChangeMasterPassword("pas-le-bon", "nouveau"); err == nil {
		t.Fatal("le changement aurait dû être refusé avec un mauvais mot de passe actuel")
	}
	if _, err := UnlockVault("ancien"); err != nil {
		t.Fatal("le mot de passe d'origine ne fonctionne plus après un échec de changement")
	}
}

func TestVaultExists(t *testing.T) {
	chdirTemp(t)

	if VaultExists() {
		t.Fatal("VaultExists() = true sur un répertoire vide")
	}
	if _, err := InitVault("mot-de-passe"); err != nil {
		t.Fatalf("InitVault() a échoué : %v", err)
	}
	if !VaultExists() {
		t.Fatal("VaultExists() = false après initialisation")
	}
}

func TestDataKeyAndDBKeyDiffer(t *testing.T) {
	chdirTemp(t)

	dek, err := InitVault("mot-de-passe")
	if err != nil {
		t.Fatalf("InitVault() a échoué : %v", err)
	}

	dataKey, err := DataKey(dek)
	if err != nil {
		t.Fatalf("DataKey() a échoué : %v", err)
	}
	dbKey, err := DBKey(dek)
	if err != nil {
		t.Fatalf("DBKey() a échoué : %v", err)
	}

	if bytes.Equal(dataKey, dbKey) {
		t.Fatal("les clés data et db sont identiques")
	}
}
