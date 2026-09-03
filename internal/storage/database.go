package storage

import (
	"database/sql"
	"fmt"
	"go-password-manager/internal/crypto"
	"net/url"

	_ "github.com/mutecomm/go-sqlcipher/v4"
)

// InitDB initialise la base de données SQLite chiffrée.
// Elle retourne une erreur plutôt que de terminer le process : appelée depuis
// des handlers HTTP, un log.Fatal ferait planter tout le serveur pour une
// seule requête en échec.
func InitDB(passphrase string) (*sql.DB, error) {
	if len(passphrase) != 32 {
		return nil, fmt.Errorf("clé de chiffrement invalide ou non définie (doit être de 32 caractères)")
	}

	db, err := sql.Open("sqlite3", "passwords.db?_pragma_key="+url.QueryEscape(passphrase))
	if err != nil {
		return nil, fmt.Errorf("erreur d'ouverture de la DB : %w", err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS passwords (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		site TEXT,
		username TEXT,
		password TEXT
	);`)
	if err != nil {
		return nil, fmt.Errorf("erreur de création de table : %w", err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS master_password (
		id INTEGER PRIMARY KEY,
		hash TEXT
	);`)
	if err != nil {
		return nil, fmt.Errorf("erreur création table master_password : %w", err)
	}

	return db, nil
}

// SetMasterPassword enregistre le mot de passe maître hashé
func SetMasterPassword(db *sql.DB, masterPassword string) error {
	hash, err := crypto.HashPassword(masterPassword)
	if err != nil {
		return err
	}

	_, err = db.Exec("INSERT INTO master_password (id, hash) VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET hash = ?", hash, hash)
	return err
}

// CheckMasterPassword vérifie si le mot de passe maître est correct
func CheckMasterPassword(db *sql.DB, enteredPassword string) bool {
	var hash string
	err := db.QueryRow("SELECT hash FROM master_password WHERE id = 1").Scan(&hash)
	if err != nil {
		fmt.Println("Mot de passe maître non défini. Exécutez `password-manager set-master` pour en définir un.")
		return false
	}

	return crypto.CompareHash(enteredPassword, hash)
}
