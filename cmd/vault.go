package cmd

import (
	"database/sql"
	"fmt"
	"go-password-manager/internal/storage"
	"os"

	"golang.org/x/term"
)

// promptPassword lit un mot de passe au clavier sans l'afficher.
func promptPassword(label string) (string, error) {
	fmt.Print(label)
	secret, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("lecture du mot de passe : %w", err)
	}
	return string(secret), nil
}

// unlockVault demande le mot de passe maître, déverrouille la clé de données
// et ouvre la base chiffrée. Le mot de passe maître n'est jamais conservé :
// seules les sous-clés dérivées sont renvoyées.
//
// Elle renvoie la base ouverte et la sous-clé servant à chiffrer/déchiffrer
// les valeurs.
func unlockVault() (*sql.DB, []byte, error) {
	if !storage.VaultExists() {
		return nil, nil, storage.ErrVaultNotInitialised
	}

	masterPassword, err := promptPassword("Mot de passe maître : ")
	if err != nil {
		return nil, nil, err
	}

	dek, err := storage.UnlockVault(masterPassword)
	if err != nil {
		return nil, nil, err
	}

	dbKey, err := storage.DBKey(dek)
	if err != nil {
		return nil, nil, err
	}

	db, err := storage.InitDB(dbKey)
	if err != nil {
		return nil, nil, err
	}

	dataKey, err := storage.DataKey(dek)
	if err != nil {
		return nil, nil, err
	}

	return db, dataKey, nil
}
