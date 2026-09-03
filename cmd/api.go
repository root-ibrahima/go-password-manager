package cmd

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"go-password-manager/internal/crypto"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/spf13/cobra"
)

// Credentials représente une requête envoyée par le client d'auto-remplissage
type Credentials struct {
	Site string `json:"site"`
	Auth string `json:"auth"`
}

// PasswordResponse représente la réponse renvoyée au client
type PasswordResponse struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var (
	db          *sql.DB
	apiDataKey  []byte
	apiListenOn = ":8080"
)

// handleGetPassword renvoie le mot de passe stocké pour un site donné
func handleGetPassword(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")

	var creds Credentials
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Requête invalide", http.StatusBadRequest)
		return
	}

	expectedToken := os.Getenv("API_TOKEN")
	if expectedToken == "" {
		http.Error(w, "Erreur serveur : API_TOKEN non défini", http.StatusInternalServerError)
		return
	}
	if subtle.ConstantTimeCompare([]byte(creds.Auth), []byte(expectedToken)) != 1 {
		http.Error(w, "Authentification refusée", http.StatusUnauthorized)
		return
	}

	row := db.QueryRow("SELECT username, password FROM passwords WHERE site = ?", creds.Site)
	var username, encryptedPassword string
	if err := row.Scan(&username, &encryptedPassword); err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Site non trouvé", http.StatusNotFound)
		} else {
			http.Error(w, "Erreur lors de la récupération des données", http.StatusInternalServerError)
		}
		return
	}

	decryptedPassword, err := crypto.Decrypt(encryptedPassword, apiDataKey)
	if err != nil {
		http.Error(w, "Erreur de déchiffrement", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	//nolint:gosec // G117: renvoyer le mot de passe déchiffré est la fonction même de cet endpoint,
	// authentifié par API_TOKEN (comparaison temps constant ci-dessus).
	if err := json.NewEncoder(w).Encode(PasswordResponse{Username: username, Password: decryptedPassword}); err != nil {
		slog.Error("erreur d'écriture de la réponse", "error", err)
	}
}

// StartServer lance le serveur API. Le mot de passe maître est demandé au
// démarrage : la clé de déchiffrement n'existe qu'en mémoire, pour la durée de
// vie du process.
func StartServer() {
	if err := godotenv.Load(); err != nil {
		slog.Warn("impossible de charger le fichier .env")
	}

	openedDB, dataKey, err := unlockVault()
	if err != nil {
		slog.Error("impossible de déverrouiller le coffre", "error", err)
		os.Exit(1)
	}
	db = openedDB
	apiDataKey = dataKey

	r := mux.NewRouter()
	r.HandleFunc("/get-password", handleGetPassword).Methods("POST")

	srv := &http.Server{
		Addr:              apiListenOn,
		Handler:           r,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		slog.Info("serveur API démarré", "url", "http://localhost"+apiListenOn)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("erreur du serveur API", "error", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	slog.Info("arrêt du serveur API en cours")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("erreur lors de l'arrêt du serveur API", "error", err)
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
