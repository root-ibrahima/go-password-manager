package cmd

import (
	"fmt"
	"go-password-manager/internal/storage"

	"github.com/spf13/cobra"
	"golang.org/x/term"
	"os"
)

// setMasterCmd définit un mot de passe maître
var setMasterCmd = &cobra.Command{
	Use:   "set-master",
	Short: "Définit le mot de passe maître",
	Run: func(cmd *cobra.Command, args []string) {
		db, err := storage.InitDB(os.Getenv("ENCRYPTION_KEY"))
		if err != nil {
			fmt.Println("Erreur :", err)
			return
		}

		fmt.Print("Entrez un mot de passe maître : ")
		masterPassword, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			fmt.Println("Erreur de lecture du mot de passe")
			return
		}

		err = storage.SetMasterPassword(db, string(masterPassword))
		if err != nil {
			fmt.Println("Erreur lors de l'enregistrement du mot de passe maître :", err)
		} else {
			fmt.Println("Mot de passe maître défini avec succès !")
		}
	},
}

func init() {
	rootCmd.AddCommand(setMasterCmd)
}
