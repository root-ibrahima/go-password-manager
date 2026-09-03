package cmd

import (
	"database/sql"
	"fmt"
	"go-password-manager/internal/crypto"
	"go-password-manager/internal/storage"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// getCmd récupère et affiche un mot de passe déchiffré
var getCmd = &cobra.Command{
	Use:   "get",
	Short: "Affiche un mot de passe déchiffré pour un site spécifique",
	Run: func(cmd *cobra.Command, args []string) {
		db, err := storage.InitDB(os.Getenv("ENCRYPTION_KEY"))
		if err != nil {
			fmt.Println("Erreur :", err)
			return
		}

		// Authentification avec le mot de passe maître
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

		// Demander le site pour lequel récupérer le mot de passe
		fmt.Print("Entrez le site (ex: example.com) : ")
		var site string
		_, _ = fmt.Scanln(&site)
		site = strings.TrimSpace(site)

		// Vérifier que le site n'est pas vide
		if site == "" {
			fmt.Println("Erreur : le site ne peut pas être vide.")
			return
		}

		// Récupérer le mot de passe chiffré depuis la base de données
		row := db.QueryRow("SELECT username, password FROM passwords WHERE site = ?", site)
		var username, encryptedPassword string
		err = row.Scan(&username, &encryptedPassword)
		if err != nil {
			if err == sql.ErrNoRows {
				fmt.Println("Aucun mot de passe trouvé pour ce site.")
			} else {
				fmt.Println("Erreur lors de la récupération du mot de passe :", err)
			}
			return
		}

		// Déchiffrer le mot de passe
		decryptedPassword, err := crypto.Decrypt(encryptedPassword)
		if err != nil {
			fmt.Println("Erreur de déchiffrement :", err)
			return
		}

		// Afficher le mot de passe déchiffré
		fmt.Printf("Identifiant : %s\n", username)
		fmt.Printf("Mot de passe : %s\n", decryptedPassword)
	},
}

func init() {
	rootCmd.AddCommand(getCmd)
}
