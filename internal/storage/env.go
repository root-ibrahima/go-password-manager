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
	if _, err := rand.Read(bytes); err != nil {
		log.Fatal("Erreur lors de la génération de la clé :", err)
	}
	return base64.StdEncoding.EncodeToString(bytes)[:length]
}

// GenerateEnvFile crée le fichier .env avec API_TOKEN s'il est absent.
//
// Depuis le passage à Argon2id, aucune clé de chiffrement n'est stockée ici :
// la clé du coffre est dérivée du mot de passe maître et enveloppée dans
// vault.key. Ce fichier ne contient donc plus que le jeton de l'API locale.
func GenerateEnvFile() {
	_ = godotenv.Load()

	apiToken := os.Getenv("API_TOKEN")
	if len(apiToken) < 32 {
		apiToken = GenerateRandomString(64)
		fmt.Println("Nouveau token API généré.")
	}

	envData := fmt.Sprintf("API_TOKEN=%s\n", apiToken)
	if err := os.WriteFile(".env", []byte(envData), 0600); err != nil { //nolint:gosec // chemin littéral, pas une entrée utilisateur
		log.Fatal("Erreur d'écriture dans .env :", err)
	}
}

// LoadEnv charge les variables d'environnement à partir de .env
func LoadEnv() {
	if err := godotenv.Load(); err != nil {
		GenerateEnvFile()
		_ = godotenv.Load()
	}

	if os.Getenv("API_TOKEN") == "" {
		GenerateEnvFile()
		_ = godotenv.Load()
	}
}
