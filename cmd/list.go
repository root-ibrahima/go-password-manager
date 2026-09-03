package cmd

import (
	"bufio"
	"fmt"
	"go-password-manager/internal/crypto"
	"go-password-manager/internal/storage"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// listCmd affiche les mots de passe enregistrés
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "Liste tous les mots de passe enregistrés",
	Run: func(cmd *cobra.Command, args []string) {
		db, err := storage.InitDB(os.Getenv("ENCRYPTION_KEY"))
		if err != nil {
			fmt.Println("Erreur :", err)
			return
		}

		// Demander le mot de passe maître
		fmt.Print("Entrez le mot de passe maître : ")
		masterPassword, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			fmt.Println("Erreur de lecture du mot de passe")
			return
		}

		if !storage.CheckMasterPassword(db, string(masterPassword)) {
			fmt.Println("Mot de passe maître incorrect ! Accès refusé.")
			return
		}

		fmt.Println("Authentification réussie ! Voici les mots de passe enregistrés :")

		rows, err := db.Query("SELECT id, site, username, password FROM passwords")
		if err != nil {
			fmt.Println("Erreur de récupération :", err)
			return
		}
		defer func() { _ = rows.Close() }()

		var passwords []struct {
			ID       int
			Site     string
			Username string
			Password string
		}

		for rows.Next() {
			var entry struct {
				ID       int
				Site     string
				Username string
				Password string
			}
			err := rows.Scan(&entry.ID, &entry.Site, &entry.Username, &entry.Password)
			if err != nil {
				fmt.Println("Erreur de lecture des données :", err)
				return
			}
			passwords = append(passwords, entry)
		}

		if len(passwords) == 0 {
			fmt.Println("Aucun mot de passe enregistré.")
			return
		}

		for _, p := range passwords {
			fmt.Printf("[%d] %s - %s\n", p.ID, p.Site, p.Username)
		}

		// Demander si l'utilisateur veut afficher les mots de passe en clair
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Voulez-vous afficher les mots de passe en clair ? (o/n) : ")
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		if choice == "o" {
			encryptionKey := os.Getenv("ENCRYPTION_KEY")
			if len(encryptionKey) != 32 {
				fmt.Println("Erreur : Clé de chiffrement invalide ou non définie")
				return
			}

			for _, p := range passwords {
				decryptedPassword, err := crypto.Decrypt(p.Password)
				if err != nil {
					fmt.Printf("[%d] %s - %s - Erreur de déchiffrement\n", p.ID, p.Site, p.Username)
				} else {
					fmt.Printf("[%d] %s - %s - %s\n", p.ID, p.Site, p.Username, decryptedPassword)
				}
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(listCmd)
}
