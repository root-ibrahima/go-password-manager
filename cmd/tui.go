package cmd

import (
	"fmt"
	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"
)

// tuiCmd lance l'interface interactive
var tuiCmd = &cobra.Command{
	Use:   "menu",
	Short: "Ouvre le menu interactif",
	Run: func(cmd *cobra.Command, args []string) {
		menu := promptui.Select{
			Label: "Sélectionnez une action",
			Items: []string{"Ajouter un mot de passe", "Lister les mots de passe", "Quitter"},
		}

		_, result, err := menu.Run()
		if err != nil {
			fmt.Println("Erreur de sélection :", err)
			return
		}

		switch result {
		case "Ajouter un mot de passe":
			execCommand("add")
		case "Lister les mots de passe":
			execCommand("list")
		case "Quitter":
			fmt.Println("👋 Au revoir !")
		}
	},
}

// execCommand exécute une commande CLI en interne
func execCommand(command string) {
	rootCmd.SetArgs([]string{command})
	_ = rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(tuiCmd)
}
