package cmd

import (
	"bufio"
	"database/sql"
	"fmt"
	"go-password-manager/internal/crypto"
	"go-password-manager/internal/storage"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// authenticateUser vérifie le mot de passe maître
func authenticateUser(db *sql.DB) bool {
	fmt.Print("Entrez le mot de passe maître : ")
	masterPassword, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		fmt.Println("Erreur de lecture du mot de passe")
		return false
	}

	if !storage.CheckMasterPassword(db, string(masterPassword)) {
		fmt.Println("Mot de passe maître incorrect !")
		return false
	}

	fmt.Println("Authentification réussie !")
	return true
}

// addCmd ajoute un mot de passe sécurisé
var addCmd = &cobra.Command{
	Use:   "add",
	Short: "Ajoute un mot de passe sécurisé",
	Run: func(cmd *cobra.Command, args []string) {
		db, err := storage.InitDB(os.Getenv("ENCRYPTION_KEY"))
		if err != nil {
			fmt.Println("Erreur :", err)
			return
		}

		if !authenticateUser(db) {
			return
		}

		reader := bufio.NewReader(os.Stdin)

		fmt.Print("Site Web : ")
		site, _ := reader.ReadString('\n')
		site = strings.TrimSpace(site)

		fmt.Print("Nom d'utilisateur : ")
		username, _ := reader.ReadString('\n')
		username = strings.TrimSpace(username)

		fmt.Print("Mot de passe (laisser vide pour générer automatiquement) : ")
		password, _ := reader.ReadString('\n')
		password = strings.TrimSpace(password)

		if password == "" {
			password = crypto.GeneratePassword(16)
			fmt.Println("Mot de passe généré :", password)
		}

		// Chiffrer le mot de passe
		encryptedPassword, err := crypto.Encrypt(password)
		if err != nil {
			fmt.Println("Erreur de chiffrement :", err)
			return
		}

		_, err = db.Exec("INSERT INTO passwords (site, username, password) VALUES (?, ?, ?)", site, username, encryptedPassword)
		if err != nil {
			fmt.Println("Erreur lors de l'ajout :", err)
		} else {
			fmt.Println("Mot de passe ajouté avec succès !")
		}
	},
}

func init() {
	rootCmd.AddCommand(addCmd)
}
