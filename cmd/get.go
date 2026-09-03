package cmd

import (
	"database/sql"
	"fmt"
	"go-password-manager/internal/crypto"
	"strings"

	"github.com/spf13/cobra"
)

// getCmd récupère et affiche un mot de passe déchiffré
var getCmd = &cobra.Command{
	Use:   "get",
	Short: "Affiche un mot de passe déchiffré pour un site spécifique",
	Run: func(cmd *cobra.Command, args []string) {
		db, dataKey, err := unlockVault()
		if err != nil {
			fmt.Println("Erreur :", err)
			return
		}
		defer func() { _ = db.Close() }()

		fmt.Print("Entrez le site (ex: example.com) : ")
		var site string
		_, _ = fmt.Scanln(&site)
		site = strings.TrimSpace(site)

		if site == "" {
			fmt.Println("Erreur : le site ne peut pas être vide.")
			return
		}

		row := db.QueryRow("SELECT username, password FROM passwords WHERE site = ?", site)
		var username, encryptedPassword string
		if err := row.Scan(&username, &encryptedPassword); err != nil {
			if err == sql.ErrNoRows {
				fmt.Println("Aucun mot de passe trouvé pour ce site.")
			} else {
				fmt.Println("Erreur lors de la récupération du mot de passe :", err)
			}
			return
		}

		decryptedPassword, err := crypto.Decrypt(encryptedPassword, dataKey)
		if err != nil {
			fmt.Println("Erreur de déchiffrement :", err)
			return
		}

		fmt.Printf("Identifiant : %s\n", username)
		fmt.Printf("Mot de passe : %s\n", decryptedPassword)
	},
}

func init() {
	rootCmd.AddCommand(getCmd)
}
