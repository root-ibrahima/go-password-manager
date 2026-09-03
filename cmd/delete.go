package cmd

import (
	"bufio"
	"fmt"
	"go-password-manager/internal/storage"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// deleteCmd supprime une entrée du coffre à partir de son identifiant.
var deleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Supprime une entrée du coffre",
	Run: func(cmd *cobra.Command, args []string) {
		db, _, err := unlockVault()
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

		for _, e := range entries {
			fmt.Printf("[%d] %s - %s\n", e.ID, e.Site, e.Username)
		}

		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Identifiant à supprimer : ")
		raw, _ := reader.ReadString('\n')

		id, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil {
			fmt.Println("Erreur : identifiant invalide.")
			return
		}

		// Suppression définitive : on demande une confirmation explicite.
		fmt.Printf("Supprimer définitivement l'entrée %d ? (o/n) : ", id)
		confirm, _ := reader.ReadString('\n')
		if strings.TrimSpace(confirm) != "o" {
			fmt.Println("Suppression annulée.")
			return
		}

		if err := storage.DeleteEntry(db, id); err != nil {
			fmt.Println("Erreur :", err)
			return
		}

		fmt.Println("Entrée supprimée.")
	},
}

func init() {
	rootCmd.AddCommand(deleteCmd)
}
