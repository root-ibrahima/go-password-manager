package storage

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"go-password-manager/internal/crypto"
	"os"
)

// VaultKeyFile contient le sel Argon2id et la clé de données enveloppée.
// Il ne contient rien d'exploitable sans le mot de passe maître.
const VaultKeyFile = "vault.key"

// ErrVaultNotInitialised est renvoyée quand aucun coffre n'existe encore.
var ErrVaultNotInitialised = errors.New("coffre non initialisé : exécutez `password-manager set-master`")

// vaultKey est la représentation sur disque du matériel de clé.
type vaultKey struct {
	Version    int    `json:"version"`
	KDF        string `json:"kdf"`
	Salt       string `json:"salt"`
	WrappedKey string `json:"wrapped_key"`
}

// InitVault crée un nouveau coffre : une clé de données (DEK) aléatoire,
// enveloppée par une clé dérivée du mot de passe maître via Argon2id.
// La DEK elle-même n'est jamais écrite en clair.
func InitVault(masterPassword string) ([]byte, error) {
	salt, err := crypto.NewSalt()
	if err != nil {
		return nil, err
	}

	dek, err := crypto.NewDEK()
	if err != nil {
		return nil, err
	}

	wrapped, err := crypto.WrapKey(crypto.DeriveKEK(masterPassword, salt), dek)
	if err != nil {
		return nil, err
	}

	if err := writeVaultKey(vaultKey{
		Version:    1,
		KDF:        "argon2id",
		Salt:       base64.StdEncoding.EncodeToString(salt),
		WrappedKey: base64.StdEncoding.EncodeToString(wrapped),
	}); err != nil {
		return nil, err
	}

	return dek, nil
}

// UnlockVault dérive la KEK depuis le mot de passe maître et déballe la DEK.
// Une erreur signifie un mot de passe incorrect (vérifié par l'authentification
// AES-GCM) ou un fichier de clé corrompu.
func UnlockVault(masterPassword string) ([]byte, error) {
	vk, err := readVaultKey()
	if err != nil {
		return nil, err
	}

	salt, err := base64.StdEncoding.DecodeString(vk.Salt)
	if err != nil {
		return nil, fmt.Errorf("sel illisible dans %s : %w", VaultKeyFile, err)
	}

	wrapped, err := base64.StdEncoding.DecodeString(vk.WrappedKey)
	if err != nil {
		return nil, fmt.Errorf("clé enveloppée illisible dans %s : %w", VaultKeyFile, err)
	}

	return crypto.UnwrapKey(crypto.DeriveKEK(masterPassword, salt), wrapped)
}

// ChangeMasterPassword ré-enveloppe la même DEK avec une clé dérivée du nouveau
// mot de passe. Les données déjà chiffrées restent valides : aucun
// re-chiffrement du coffre n'est nécessaire.
func ChangeMasterPassword(oldPassword, newPassword string) error {
	dek, err := UnlockVault(oldPassword)
	if err != nil {
		return err
	}

	salt, err := crypto.NewSalt()
	if err != nil {
		return err
	}

	wrapped, err := crypto.WrapKey(crypto.DeriveKEK(newPassword, salt), dek)
	if err != nil {
		return err
	}

	return writeVaultKey(vaultKey{
		Version:    1,
		KDF:        "argon2id",
		Salt:       base64.StdEncoding.EncodeToString(salt),
		WrappedKey: base64.StdEncoding.EncodeToString(wrapped),
	})
}

// VaultExists indique si un coffre a déjà été initialisé.
func VaultExists() bool {
	_, err := os.Stat(VaultKeyFile)
	return err == nil
}

// DataKey et DBKey dérivent les sous-clés d'usage depuis la DEK.
func DataKey(dek []byte) ([]byte, error) { return crypto.SubKey(dek, crypto.PurposeData) }
func DBKey(dek []byte) ([]byte, error)   { return crypto.SubKey(dek, crypto.PurposeDB) }

func writeVaultKey(vk vaultKey) error {
	data, err := json.MarshalIndent(vk, "", "  ")
	if err != nil {
		return fmt.Errorf("sérialisation de la clé du coffre : %w", err)
	}
	if err := os.WriteFile(VaultKeyFile, data, 0600); err != nil {
		return fmt.Errorf("écriture de %s : %w", VaultKeyFile, err)
	}
	return nil
}

func readVaultKey() (vaultKey, error) {
	var vk vaultKey

	data, err := os.ReadFile(VaultKeyFile)
	if err != nil {
		if os.IsNotExist(err) {
			return vk, ErrVaultNotInitialised
		}
		return vk, fmt.Errorf("lecture de %s : %w", VaultKeyFile, err)
	}

	if err := json.Unmarshal(data, &vk); err != nil {
		return vk, fmt.Errorf("%s illisible : %w", VaultKeyFile, err)
	}
	if vk.KDF != "argon2id" {
		return vk, fmt.Errorf("KDF non supporté dans %s : %q", VaultKeyFile, vk.KDF)
	}
	return vk, nil
}
