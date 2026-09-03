package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// Encrypt chiffre un texte avec AES-256-GCM. La clé est fournie par l'appelant
// (sous-clé « data » dérivée de la DEK) : rien n'est lu depuis l'environnement,
// aucune clé ne traîne dans un fichier en clair.
func Encrypt(data string, key []byte) (string, error) {
	if len(key) != KeyLen {
		return "", fmt.Errorf("clé de chiffrement invalide (%d octets, %d attendus)", len(key), KeyLen)
	}

	aesGCM, err := newGCM(key)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("génération du nonce : %w", err)
	}

	cipherText := aesGCM.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

// Decrypt déchiffre un texte produit par Encrypt avec la même clé.
func Decrypt(encryptedData string, key []byte) (string, error) {
	if len(key) != KeyLen {
		return "", fmt.Errorf("clé de chiffrement invalide (%d octets, %d attendus)", len(key), KeyLen)
	}

	data, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", errors.New("données chiffrées invalides")
	}

	aesGCM, err := newGCM(key)
	if err != nil {
		return "", err
	}

	if len(data) < aesGCM.NonceSize() {
		return "", errors.New("données invalides ou corrompues")
	}

	nonce := data[:aesGCM.NonceSize()]
	plainText, err := aesGCM.Open(nil, nonce, data[aesGCM.NonceSize():], nil)
	if err != nil {
		return "", errors.New("échec du déchiffrement (clé incorrecte ou données corrompues)")
	}

	return string(plainText), nil
}
