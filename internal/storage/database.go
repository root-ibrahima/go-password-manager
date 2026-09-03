package storage

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"go-password-manager/internal/crypto"
	"net/url"
	"os"

	_ "github.com/mutecomm/go-sqlcipher/v4"
)

// DBFile est le fichier SQLCipher contenant les entrées du coffre.
const DBFile = "passwords.db"

// InitDB ouvre la base SQLCipher avec la sous-clé « db » dérivée de la DEK.
// Elle retourne une erreur plutôt que de terminer le process : appelée depuis
// des handlers HTTP, un log.Fatal ferait planter tout le serveur pour une
// seule requête en échec.
func InitDB(dbKey []byte) (*sql.DB, error) {
	if len(dbKey) != crypto.KeyLen {
		return nil, fmt.Errorf("clé de base invalide (%d octets, %d attendus)", len(dbKey), crypto.KeyLen)
	}

	// La clé est passée en hexadécimal : 64 caractères sûrs pour une chaîne de
	// connexion, avec les 256 bits d'entropie d'origine.
	passphrase := hex.EncodeToString(dbKey)

	db, err := sql.Open("sqlite3", DBFile+"?_pragma_key="+url.QueryEscape(passphrase))
	if err != nil {
		return nil, fmt.Errorf("erreur d'ouverture de la DB : %w", err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS passwords (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		site TEXT NOT NULL,
		username TEXT NOT NULL,
		password TEXT NOT NULL
	);`)
	if err != nil {
		return nil, fmt.Errorf("erreur de création de table : %w", err)
	}

	// La base est aussi sensible que le fichier de clé : elle ne doit pas être
	// lisible par les autres utilisateurs de la machine.
	if err := os.Chmod(DBFile, 0600); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("restriction des permissions de %s : %w", DBFile, err)
	}

	return db, nil
}

// Entry est une entrée du coffre. Password reste chiffré tant qu'il n'a pas
// été explicitement déchiffré par l'appelant.
type Entry struct {
	ID       int
	Site     string
	Username string
	Password string
}

// AddEntry insère une entrée dont le mot de passe est déjà chiffré.
func AddEntry(db *sql.DB, site, username, encryptedPassword string) error {
	_, err := db.Exec(
		"INSERT INTO passwords (site, username, password) VALUES (?, ?, ?)",
		site, username, encryptedPassword,
	)
	return err
}

// ListEntries renvoie toutes les entrées, mots de passe encore chiffrés.
func ListEntries(db *sql.DB) ([]Entry, error) {
	rows, err := db.Query("SELECT id, site, username, password FROM passwords ORDER BY site")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var entries []Entry
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.ID, &e.Site, &e.Username, &e.Password); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// DeleteEntry supprime une entrée par son identifiant. Elle signale le cas où
// aucune ligne ne correspond, pour éviter de faire croire à une suppression.
func DeleteEntry(db *sql.DB, id int) error {
	res, err := db.Exec("DELETE FROM passwords WHERE id = ?", id)
	if err != nil {
		return err
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("aucune entrée avec l'identifiant %d", id)
	}
	return nil
}
