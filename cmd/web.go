package cmd

import (
	"go-password-manager/web"

	"github.com/spf13/cobra"
)

// webCmd lance l'interface web (login mot de passe maître, liste et ajout).
var webCmd = &cobra.Command{
	Use:   "web",
	Short: "Démarre l'interface web",
	Run: func(cmd *cobra.Command, args []string) {
		web.StartServer()
	},
}

func init() {
	rootCmd.AddCommand(webCmd)
}
