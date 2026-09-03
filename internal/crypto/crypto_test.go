package crypto

import "testing"

const testKey = "01234567890123456789012345678901" // 32 caractères

func TestEncryptDecryptRoundTrip(t *testing.T) {
	t.Setenv("ENCRYPTION_KEY", testKey)

	plainText := "hunter2"
	cipherText, err := Encrypt(plainText)
	if err != nil {
		t.Fatalf("Encrypt() a échoué : %v", err)
	}
	if cipherText == plainText {
		t.Fatal("Encrypt() a renvoyé le texte en clair")
	}

	decrypted, err := Decrypt(cipherText)
	if err != nil {
		t.Fatalf("Decrypt() a échoué : %v", err)
	}
	if decrypted != plainText {
		t.Fatalf("Decrypt() = %q, attendu %q", decrypted, plainText)
	}
}

func TestEncryptMissingKey(t *testing.T) {
	t.Setenv("ENCRYPTION_KEY", "")

	if _, err := Encrypt("secret"); err == nil {
		t.Fatal("Encrypt() aurait dû échouer sans ENCRYPTION_KEY valide")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	t.Setenv("ENCRYPTION_KEY", testKey)
	cipherText, err := Encrypt("secret")
	if err != nil {
		t.Fatalf("Encrypt() a échoué : %v", err)
	}

	t.Setenv("ENCRYPTION_KEY", "98765432109876543210987654321098")
	if _, err := Decrypt(cipherText); err == nil {
		t.Fatal("Decrypt() aurait dû échouer avec une clé différente")
	}
}

func TestDecryptInvalidData(t *testing.T) {
	t.Setenv("ENCRYPTION_KEY", testKey)

	if _, err := Decrypt("pas-du-base64-valide!!"); err == nil {
		t.Fatal("Decrypt() aurait dû échouer sur des données invalides")
	}
}

func TestHashPasswordAndCompareHash(t *testing.T) {
	hash, err := HashPassword("hunter2")
	if err != nil {
		t.Fatalf("HashPassword() a échoué : %v", err)
	}

	if !CompareHash("hunter2", hash) {
		t.Fatal("CompareHash() aurait dû accepter le bon mot de passe")
	}
	if CompareHash("wrong-password", hash) {
		t.Fatal("CompareHash() aurait dû rejeter un mauvais mot de passe")
	}
}

func TestGeneratePassword(t *testing.T) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"

	password := GeneratePassword(20)
	if len(password) != 20 {
		t.Fatalf("longueur du mot de passe = %d, attendu 20", len(password))
	}
	for _, c := range password {
		if !contains(charset, c) {
			t.Fatalf("caractère %q hors du charset attendu", c)
		}
	}

	first := GeneratePassword(20)
	second := GeneratePassword(20)
	if first == second {
		t.Fatal("deux mots de passe générés sont identiques (collision improbable)")
	}
}

func contains(charset string, c rune) bool {
	for _, allowed := range charset {
		if allowed == c {
			return true
		}
	}
	return false
}
