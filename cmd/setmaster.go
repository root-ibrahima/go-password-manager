package cmd

import (
	"fmt"
	"go-password-manager/internal/storage"

	"github.com/spf13/cobra"
)

// setMasterCmd initialise le coffre ou change le mot de passe maître.
var setMasterCmd = &cobra.Command{
	Use:   "set-master",
	Short: "Initialise le coffre ou change le mot de passe maître",
	Run: func(cmd *cobra.Command, args []string) {
		if storage.VaultExists() {
			changeMasterPassword()
			return
		}
		initialiseVault()
	},
}

// initialiseVault crée le coffre au premier lancement.
func initialiseVault() {
	password, err := promptPassword("Choisissez un mot de passe maître : ")
	if err != nil {
		fmt.Println("Erreur :", err)
		return
	}
	if password == "" {
		fmt.Println("Erreur : le mot de passe maître ne peut pas être vide.")
		return
	}

	confirmation, err := promptPassword("Confirmez le mot de passe maître : ")
	if err != nil {
		fmt.Println("Erreur :", err)
		return
	}
	if password != confirmation {
		fmt.Println("Erreur : les deux saisies ne correspondent pas.")
		return
	}

	dek, err := storage.InitVault(password)
	if err != nil {
		fmt.Println("Erreur lors de l'initialisation du coffre :", err)
		return
	}

	// Crée la base immédiatement, pour que le coffre soit utilisable ensuite.
	dbKey, err := storage.DBKey(dek)
	if err != nil {
		fmt.Println("Erreur :", err)
		return
	}
	db, err := storage.InitDB(dbKey)
	if err != nil {
		fmt.Println("Erreur lors de la création de la base :", err)
		return
	}
	defer func() { _ = db.Close() }()

	fmt.Println("Coffre initialisé. La clé de chiffrement est dérivée de votre mot de passe maître (Argon2id).")
}

// changeMasterPassword ré-enveloppe la clé de données avec un nouveau mot de
// passe. Les entrées existantes restent lisibles : elles ne sont pas
// re-chiffrées, seule la clé est ré-enveloppée.
func changeMasterPassword() {
	current, err := promptPassword("Mot de passe maître actuel : ")
	if err != nil {
		fmt.Println("Erreur :", err)
		return
	}

	newPassword, err := promptPassword("Nouveau mot de passe maître : ")
	if err != nil {
		fmt.Println("Erreur :", err)
		return
	}
	if newPassword == "" {
		fmt.Println("Erreur : le mot de passe maître ne peut pas être vide.")
		return
	}

	confirmation, err := promptPassword("Confirmez le nouveau mot de passe : ")
	if err != nil {
		fmt.Println("Erreur :", err)
		return
	}
	if newPassword != confirmation {
		fmt.Println("Erreur : les deux saisies ne correspondent pas.")
		return
	}

	if err := storage.ChangeMasterPassword(current, newPassword); err != nil {
		fmt.Println("Erreur :", err)
		return
	}

	fmt.Println("Mot de passe maître mis à jour. Vos entrées restent inchangées.")
}

func init() {
	rootCmd.AddCommand(setMasterCmd)
}
