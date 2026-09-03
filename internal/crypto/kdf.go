package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// Paramètres Argon2id. Ils suivent l'option recommandée par la RFC 9106 pour
// un usage interactif (64 Mio, 3 passes, 4 voies), soit ~100 ms par dérivation
// sur une machine de bureau : assez rapide pour l'utilisateur, assez coûteux
// pour rendre une attaque par dictionnaire hors ligne peu rentable.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // en Kio
	argonThreads = 4
	KeyLen       = 32 // AES-256
	SaltLen      = 16
)

// DeriveKEK dérive la clé de chiffrement de clé (KEK) à partir du mot de passe
// maître. Cette clé ne chiffre jamais de données : elle sert uniquement à
// envelopper la clé de données (DEK).
func DeriveKEK(masterPassword string, salt []byte) []byte {
	return argon2.IDKey([]byte(masterPassword), salt, argonTime, argonMemory, argonThreads, KeyLen)
}

// NewSalt génère un sel aléatoire pour la dérivation Argon2id.
func NewSalt() ([]byte, error) {
	salt := make([]byte, SaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("génération du sel : %w", err)
	}
	return salt, nil
}

// NewDEK génère une clé de données aléatoire (32 octets).
func NewDEK() ([]byte, error) {
	dek := make([]byte, KeyLen)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("génération de la clé de données : %w", err)
	}
	return dek, nil
}

// WrapKey chiffre la DEK avec la KEK (AES-256-GCM). Le nonce est préfixé au
// texte chiffré.
func WrapKey(kek, dek []byte) ([]byte, error) {
	aesGCM, err := newGCM(kek)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("génération du nonce : %w", err)
	}

	return aesGCM.Seal(nonce, nonce, dek, nil), nil
}

// UnwrapKey déchiffre la DEK avec la KEK. Un échec signifie que le mot de passe
// maître est incorrect : l'authentification GCM sert ici de vérification du mot
// de passe, ce qui est plus fort qu'une simple comparaison de hash (il faut
// réellement pouvoir déchiffrer, pas seulement connaître une valeur).
func UnwrapKey(kek, wrapped []byte) ([]byte, error) {
	aesGCM, err := newGCM(kek)
	if err != nil {
		return nil, err
	}

	if len(wrapped) < aesGCM.NonceSize() {
		return nil, errors.New("clé enveloppée invalide ou corrompue")
	}

	nonce := wrapped[:aesGCM.NonceSize()]
	dek, err := aesGCM.Open(nil, nonce, wrapped[aesGCM.NonceSize():], nil)
	if err != nil {
		return nil, errors.New("mot de passe maître incorrect")
	}
	return dek, nil
}

// SubKey dérive une sous-clé dédiée à un usage précis à partir de la DEK
// (HKDF-SHA256). On ne réutilise jamais la même clé pour deux usages
// différents : une pour le chiffrement des valeurs, une pour SQLCipher.
func SubKey(dek []byte, purpose string) ([]byte, error) {
	reader := hkdf.New(sha256.New, dek, nil, []byte(purpose))
	key := make([]byte, KeyLen)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, fmt.Errorf("dérivation de la sous-clé %q : %w", purpose, err)
	}
	return key, nil
}

// Usages des sous-clés dérivées de la DEK.
const (
	PurposeData = "securepass:v1:data" // chiffrement AES-GCM des mots de passe
	PurposeDB   = "securepass:v1:db"   // passphrase SQLCipher
)

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("création du cipher : %w", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("création de l'instance AES-GCM : %w", err)
	}
	return aesGCM, nil
}
