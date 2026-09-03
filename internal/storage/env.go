package storage

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
)

// GenerateRandomString génère une chaîne aléatoire sécurisée
func GenerateRandomString(length int) string {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		log.Fatal("Erreur lors de la génération de la clé :", err)
	}
	return base64.StdEncoding.EncodeToString(bytes)[:length]
}

// GenerateEnvFile crée un fichier .env avec ENCRYPTION_KEY et API_TOKEN si absents
func GenerateEnvFile() {
	envFile := ".env"

	// Charger les variables existantes (si le fichier existe)
	_ = godotenv.Load()

	// Vérifier si les variables sont déjà définies
	encryptionKey := os.Getenv("ENCRYPTION_KEY")
	apiToken := os.Getenv("API_TOKEN")

	// Générer une nouvelle clé si absente ou invalide
	if len(encryptionKey) != 32 {
		encryptionKey = GenerateRandomString(32)
		fmt.Println("Nouvelle clé de chiffrement générée.")
	}

	if len(apiToken) < 32 {
		apiToken = GenerateRandomString(64)
		fmt.Println("Nouveau token API généré.")
	}

	// Écrire dans le fichier .env
	envData := fmt.Sprintf("ENCRYPTION_KEY=%s\nAPI_TOKEN=%s\n", encryptionKey, apiToken)
	err := os.WriteFile(envFile, []byte(envData), 0600) //nolint:gosec // envFile est la constante littérale ".env", pas une entrée utilisateur
	if err != nil {
		log.Fatal("Erreur d'écriture dans .env :", err)
	}

	fmt.Println("Fichier .env mis à jour avec succès.")
}

// LoadEnv charge les variables d'environnement à partir de .env
func LoadEnv() {
	err := godotenv.Load()
	if err != nil {
		log.Println("Avertissement : Impossible de charger le fichier .env. Assurez-vous qu'il existe.")

		// Générer le fichier .env si absent
		GenerateEnvFile()
		_ = godotenv.Load() // Recharger après création
	}

	// Vérifier que API_TOKEN est bien défini
	if os.Getenv("API_TOKEN") == "" {
		log.Fatal("Erreur : API_TOKEN non défini dans .env")
	}

	// Vérifier que ENCRYPTION_KEY est bien défini et a la bonne longueur
	if len(os.Getenv("ENCRYPTION_KEY")) != 32 {
		log.Fatal("Erreur : ENCRYPTION_KEY doit être une clé de 32 caractères dans .env")
	}
}
