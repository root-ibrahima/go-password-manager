package cmd

import (
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"go-password-manager/internal/crypto"
	"go-password-manager/internal/storage"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/spf13/cobra"
)

// Credentials représente une requête envoyée par l'extension
type Credentials struct {
	Site string `json:"site"`
	Auth string `json:"auth"`
}

// PasswordResponse représente la réponse envoyée à l'extension
type PasswordResponse struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var db *sql.DB

// handleGetPassword renvoie le mot de passe stocké pour un site donné
func handleGetPassword(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "Requête invalide", http.StatusBadRequest)
		return
	}

	// Vérifier l'authentification via un token
	expectedToken := os.Getenv("API_TOKEN")
	if expectedToken == "" {
		http.Error(w, "Erreur serveur : API_TOKEN non défini", http.StatusInternalServerError)
		return
	}
	if subtle.ConstantTimeCompare([]byte(creds.Auth), []byte(expectedToken)) != 1 {
		http.Error(w, "Authentification refusée", http.StatusUnauthorized)
		return
	}

	// Rechercher le mot de passe dans la base de données
	row := db.QueryRow("SELECT username, password FROM passwords WHERE site = ?", creds.Site)
	var username, encryptedPassword string
	err = row.Scan(&username, &encryptedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Site non trouvé", http.StatusNotFound)
		} else {
			http.Error(w, "Erreur lors de la récupération des données", http.StatusInternalServerError)
		}
		return
	}

	// Déchiffrer le mot de passe
	decryptedPassword, err := crypto.Decrypt(encryptedPassword)
	if err != nil {
		http.Error(w, "Erreur de déchiffrement", http.StatusInternalServerError)
		return
	}

	// Réponse JSON sécurisée
	w.Header().Set("Content-Type", "application/json")
	//nolint:gosec // G117: renvoyer le mot de passe déchiffré est la fonction même de cet endpoint,
	// authentifié par API_TOKEN (comparaison temps constant ci-dessus), consommé par l'extension navigateur.
	if err := json.NewEncoder(w).Encode(PasswordResponse{Username: username, Password: decryptedPassword}); err != nil {
		slog.Error("erreur d'écriture de la réponse", "error", err)
	}
}

// StartServer lance le serveur API
func StartServer() {
	err := godotenv.Load()
	if err != nil {
		slog.Warn("impossible de charger le fichier .env")
	}

	db, err = storage.InitDB(os.Getenv("ENCRYPTION_KEY"))
	if err != nil {
		slog.Error("erreur d'initialisation de la base de données", "error", err)
		os.Exit(1)
	}

	// Création du routeur
	r := mux.NewRouter()
	r.HandleFunc("/get-password", handleGetPassword).Methods("POST")

	// Démarrage du serveur API
	slog.Info("serveur API démarré", "url", "http://localhost:8080")
	srv := &http.Server{
		Addr:              ":8080",
		Handler:           r,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		slog.Error("erreur du serveur API", "error", err)
		os.Exit(1)
	}
}

var apiCmd = &cobra.Command{
	Use:   "api",
	Short: "Démarre le serveur API",
	Run: func(cmd *cobra.Command, args []string) {
		StartServer()
	},
}

func init() {
	rootCmd.AddCommand(apiCmd)
}
