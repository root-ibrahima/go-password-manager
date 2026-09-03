package main

import (
	"fmt"
	"go-password-manager/cmd"
	"go-password-manager/internal/storage"
)

func main() {
	fmt.Println("Secure Password Manager")

	// Générer .env si nécessaire
	storage.GenerateEnvFile()

	// Charger les variables d'environnement
	storage.LoadEnv()

	// Exécuter les commandes CLI (dont `web` pour l'interface web)
	cmd.Execute()
}
