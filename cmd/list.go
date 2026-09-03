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

// listCmd affiche les mots de passe enregistrés
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "Liste tous les mots de passe enregistrés",
	Run: func(cmd *cobra.Command, args []string) {
		db, dataKey, err := unlockVault()
		if err != nil {
			fmt.Println("Erreur :", err)
			return
		}
		defer func() { _ = db.Close() }()

		entries, err := storage.ListEntries(db)
		if err != nil {
			fmt.Println("Erreur de récupération :", err)
			return
		}

		if len(entries) == 0 {
			fmt.Println("Aucun mot de passe enregistré.")
			return
		}

		fmt.Println("Entrées enregistrées :")
		for _, e := range entries {
			fmt.Printf("[%d] %s - %s\n", e.ID, e.Site, e.Username)
		}

		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Afficher les mots de passe en clair ? (o/n) : ")
		choice, _ := reader.ReadString('\n')

		if strings.TrimSpace(choice) != "o" {
			return
		}

		for _, e := range entries {
			decrypted, err := crypto.Decrypt(e.Password, dataKey)
			if err != nil {
				fmt.Printf("[%d] %s - %s - erreur de déchiffrement\n", e.ID, e.Site, e.Username)
				continue
			}
			fmt.Printf("[%d] %s - %s - %s\n", e.ID, e.Site, e.Username, decrypted)
		}
	},
}

func init() {
	rootCmd.AddCommand(listCmd)
}
