package crypto

import (
	"bytes"
	"strings"
	"testing"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	key, err := NewDEK()
	if err != nil {
		t.Fatalf("NewDEK() a échoué : %v", err)
	}
	return key
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := testKey(t)
	plainText := "hunter2"

	cipherText, err := Encrypt(plainText, key)
	if err != nil {
		t.Fatalf("Encrypt() a échoué : %v", err)
	}
	if strings.Contains(cipherText, plainText) {
		t.Fatal("le texte chiffré contient le texte en clair")
	}

	decrypted, err := Decrypt(cipherText, key)
	if err != nil {
		t.Fatalf("Decrypt() a échoué : %v", err)
	}
	if decrypted != plainText {
		t.Fatalf("Decrypt() = %q, attendu %q", decrypted, plainText)
	}
}

func TestEncryptUsesFreshNonce(t *testing.T) {
	key := testKey(t)

	first, err := Encrypt("même message", key)
	if err != nil {
		t.Fatalf("Encrypt() a échoué : %v", err)
	}
	second, err := Encrypt("même message", key)
	if err != nil {
		t.Fatalf("Encrypt() a échoué : %v", err)
	}

	// Un nonce réutilisé serait une faute grave en GCM : deux chiffrements du
	// même clair doivent produire des sorties différentes.
	if first == second {
		t.Fatal("deux chiffrements identiques : le nonce n'est pas renouvelé")
	}
}

func TestEncryptRejectsBadKeyLength(t *testing.T) {
	if _, err := Encrypt("secret", []byte("trop-courte")); err == nil {
		t.Fatal("Encrypt() aurait dû refuser une clé de mauvaise taille")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	cipherText, err := Encrypt("secret", testKey(t))
	if err != nil {
		t.Fatalf("Encrypt() a échoué : %v", err)
	}

	if _, err := Decrypt(cipherText, testKey(t)); err == nil {
		t.Fatal("Decrypt() aurait dû échouer avec une autre clé")
	}
}

func TestDecryptDetectsTampering(t *testing.T) {
	key := testKey(t)
	cipherText, err := Encrypt("secret", key)
	if err != nil {
		t.Fatalf("Encrypt() a échoué : %v", err)
	}

	// On altère un caractère du base64 : GCM étant authentifié, l'ouverture
	// doit échouer plutôt que de renvoyer des données corrompues.
	tampered := []byte(cipherText)
	if tampered[len(tampered)-2] == 'A' {
		tampered[len(tampered)-2] = 'B'
	} else {
		tampered[len(tampered)-2] = 'A'
	}

	if _, err := Decrypt(string(tampered), key); err == nil {
		t.Fatal("Decrypt() aurait dû détecter l'altération")
	}
}

func TestDecryptInvalidData(t *testing.T) {
	if _, err := Decrypt("pas-du-base64-valide!!", testKey(t)); err == nil {
		t.Fatal("Decrypt() aurait dû échouer sur des données invalides")
	}
}

func TestGeneratePassword(t *testing.T) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"

	password := GeneratePassword(20)
	if len(password) != 20 {
		t.Fatalf("longueur du mot de passe = %d, attendu 20", len(password))
	}
	for _, c := range password {
		if !strings.ContainsRune(charset, c) {
			t.Fatalf("caractère %q hors du charset attendu", c)
		}
	}

	first := GeneratePassword(20)
	second := GeneratePassword(20)
	if first == second {
		t.Fatal("deux mots de passe générés sont identiques (collision improbable)")
	}
}

func TestGeneratePasswordDistribution(t *testing.T) {
	// Le rejet d'échantillonnage doit produire une distribution ~uniforme.
	// Sans lui, les premiers caractères du charset seraient sur-représentés.
	const draws = 20000
	counts := map[rune]int{}
	for _, c := range GeneratePassword(draws) {
		counts[c]++
	}

	expected := float64(draws) / 72.0
	for c, n := range counts {
		deviation := float64(n)/expected - 1
		if deviation < -0.25 || deviation > 0.25 {
			t.Fatalf("caractère %q : écart de %.1f%% à l'uniforme", c, deviation*100)
		}
	}
}

func TestWrapUnwrapKey(t *testing.T) {
	salt, err := NewSalt()
	if err != nil {
		t.Fatalf("NewSalt() a échoué : %v", err)
	}
	dek := testKey(t)

	kek := DeriveKEK("mot-de-passe-maître", salt)
	wrapped, err := WrapKey(kek, dek)
	if err != nil {
		t.Fatalf("WrapKey() a échoué : %v", err)
	}
	if bytes.Contains(wrapped, dek) {
		t.Fatal("la clé de données apparaît en clair dans la clé enveloppée")
	}

	unwrapped, err := UnwrapKey(DeriveKEK("mot-de-passe-maître", salt), wrapped)
	if err != nil {
		t.Fatalf("UnwrapKey() a échoué : %v", err)
	}
	if !bytes.Equal(unwrapped, dek) {
		t.Fatal("la clé déballée diffère de la clé d'origine")
	}
}

func TestUnwrapKeyWrongPassword(t *testing.T) {
	salt, _ := NewSalt()
	dek := testKey(t)
	wrapped, err := WrapKey(DeriveKEK("bon-mot-de-passe", salt), dek)
	if err != nil {
		t.Fatalf("WrapKey() a échoué : %v", err)
	}

	if _, err := UnwrapKey(DeriveKEK("mauvais-mot-de-passe", salt), wrapped); err == nil {
		t.Fatal("UnwrapKey() aurait dû échouer avec un mauvais mot de passe")
	}
}

func TestDeriveKEKIsSaltDependent(t *testing.T) {
	saltA, _ := NewSalt()
	saltB, _ := NewSalt()

	if bytes.Equal(DeriveKEK("identique", saltA), DeriveKEK("identique", saltB)) {
		t.Fatal("le même mot de passe donne la même clé avec deux sels différents")
	}
	if !bytes.Equal(DeriveKEK("identique", saltA), DeriveKEK("identique", saltA)) {
		t.Fatal("la dérivation n'est pas déterministe pour un même sel")
	}
}

func TestSubKeySeparation(t *testing.T) {
	dek := testKey(t)

	dataKey, err := SubKey(dek, PurposeData)
	if err != nil {
		t.Fatalf("SubKey(data) a échoué : %v", err)
	}
	dbKey, err := SubKey(dek, PurposeDB)
	if err != nil {
		t.Fatalf("SubKey(db) a échoué : %v", err)
	}

	if bytes.Equal(dataKey, dbKey) {
		t.Fatal("les sous-clés data et db sont identiques : pas de séparation des usages")
	}
	if bytes.Equal(dataKey, dek) {
		t.Fatal("la sous-clé data est égale à la DEK")
	}
	if len(dataKey) != KeyLen {
		t.Fatalf("taille de sous-clé = %d, attendu %d", len(dataKey), KeyLen)
	}

	again, _ := SubKey(dek, PurposeData)
	if !bytes.Equal(dataKey, again) {
		t.Fatal("la dérivation de sous-clé n'est pas déterministe")
	}
}
