package crypto

import (
	"crypto/rand"
	"log"
)

// GeneratePassword crée un mot de passe aléatoire sécurisé à l'aide de
// crypto/rand, avec un rejet d'échantillonnage pour éviter tout biais modulo.
func GeneratePassword(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
	const charsetLen = len(charset)

	// Plus grand multiple de charsetLen qui tient dans un octet (0-255).
	// On rejette tout octet >= cette limite pour éviter le biais modulo.
	maxValid := byte(256 - (256 % charsetLen))

	password := make([]byte, length)
	buf := make([]byte, 1)
	for i := range password {
		for {
			if _, err := rand.Read(buf); err != nil {
				log.Fatal("Erreur lors de la génération du mot de passe :", err)
			}
			if buf[0] < maxValid {
				password[i] = charset[buf[0]%byte(charsetLen)]
				break
			}
		}
	}

	return string(password)
}
