package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
)

// getEncryptionKey récupère la clé de chiffrement depuis l'environnement
func getEncryptionKey() (string, error) {
	key := os.Getenv("ENCRYPTION_KEY")
	if len(key) != 32 {
		return "", errors.New("clé de chiffrement invalide ou non définie (doit être de 32 caractères)")
	}
	return key, nil
}

// Encrypt chiffre un texte avec AES-GCM en utilisant la clé stockée dans l'environnement
func Encrypt(data string) (string, error) {
	key, err := getEncryptionKey()
	if err != nil {
		fmt.Println("Erreur de chiffrement :", err)
		return "", err
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", fmt.Errorf("erreur lors de la création du cipher : %v", err)
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("erreur lors de la génération du nonce : %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("erreur lors de la création de l'instance AES-GCM : %v", err)
	}

	cipherText := aesGCM.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

// Decrypt déchiffre un texte chiffré avec AES-GCM en utilisant la clé stockée dans l'environnement
func Decrypt(encryptedData string) (string, error) {
	key, err := getEncryptionKey()
	if err != nil {
		fmt.Println("Erreur de déchiffrement :", err)
		return "", err
	}

	data, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", errors.New("données chiffrées invalides")
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", fmt.Errorf("erreur lors de la création du cipher : %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("erreur lors de la création de l'instance AES-GCM : %v", err)
	}

	if len(data) < aesGCM.NonceSize() {
		return "", errors.New("données invalides ou corrompues")
	}

	nonce := data[:aesGCM.NonceSize()]
	cipherText := data[aesGCM.NonceSize():]

	plainText, err := aesGCM.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return "", errors.New("échec du déchiffrement (clé incorrecte ou données corrompues)")
	}

	return string(plainText), nil
}
