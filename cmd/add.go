package cmd

import (
	"bufio"
	"fmt"
	"go-password-manager/internal/crypto"
	"go-password-manager/internal/storage"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// addCmd ajoute un mot de passe sécurisé
var addCmd = &cobra.Command{
	Use:   "add",
	Short: "Ajoute un mot de passe sécurisé",
	Run: func(cmd *cobra.Command, args []string) {
		db, dataKey, err := unlockVault()
		if err != nil {
			fmt.Println("Erreur :", err)
			return
		}
		defer func() { _ = db.Close() }()

		reader := bufio.NewReader(os.Stdin)

		fmt.Print("Site Web : ")
		site, _ := reader.ReadString('\n')
		site = strings.TrimSpace(site)

		fmt.Print("Nom d'utilisateur : ")
		username, _ := reader.ReadString('\n')
		username = strings.TrimSpace(username)

		if site == "" || username == "" {
			fmt.Println("Erreur : le site et le nom d'utilisateur sont obligatoires.")
			return
		}

		password, err := promptPassword("Mot de passe (laisser vide pour en générer un) : ")
		if err != nil {
			fmt.Println("Erreur :", err)
			return
		}

		if password == "" {
			password = crypto.GeneratePassword(16)
			fmt.Println("Mot de passe généré :", password)
		}

		encryptedPassword, err := crypto.Encrypt(password, dataKey)
		if err != nil {
			fmt.Println("Erreur de chiffrement :", err)
			return
		}

		if err := storage.AddEntry(db, site, username, encryptedPassword); err != nil {
			fmt.Println("Erreur lors de l'ajout :", err)
			return
		}

		fmt.Println("Mot de passe ajouté avec succès !")
	},
}

func init() {
	rootCmd.AddCommand(addCmd)
}
