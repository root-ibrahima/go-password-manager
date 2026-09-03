package web

import (
	"net/http/httptest"
	"testing"
	"time"
)

// resetState remet à zéro les états globaux partagés entre tests.
func resetState(t *testing.T) {
	t.Helper()

	sessionsMutex.Lock()
	sessions = make(map[string]sessionData)
	sessionsMutex.Unlock()

	loginAttemptsMutex.Lock()
	loginAttempts = make(map[string][]time.Time)
	loginAttemptsMutex.Unlock()
}

func TestCreateAndValidateSession(t *testing.T) {
	resetState(t)

	token, csrf := createSession([]byte("clé-de-données"))
	if token == "" || csrf == "" {
		t.Fatal("createSession() a renvoyé un jeton vide")
	}
	if token == csrf {
		t.Fatal("le jeton de session et le jeton CSRF sont identiques")
	}
	if len(token) != 64 {
		t.Fatalf("longueur du jeton = %d, attendu 64 (32 octets en hexa)", len(token))
	}

	if !validateSession(token) {
		t.Fatal("la session créée est jugée invalide")
	}
	if validateSession("jeton-inconnu") {
		t.Fatal("un jeton inconnu est accepté")
	}
	if validateSession("") {
		t.Fatal("un jeton vide est accepté")
	}
}

func TestSessionsAreUnique(t *testing.T) {
	resetState(t)

	first, _ := createSession(nil)
	second, _ := createSession(nil)
	if first == second {
		t.Fatal("deux sessions partagent le même jeton")
	}
}

func TestExpiredSessionIsRejected(t *testing.T) {
	resetState(t)

	token, _ := createSession(nil)

	// On force l'expiration dans le passé.
	sessionsMutex.Lock()
	data := sessions[token]
	data.expiry = time.Now().Add(-time.Minute)
	sessions[token] = data
	sessionsMutex.Unlock()

	if validateSession(token) {
		t.Fatal("une session expirée est acceptée")
	}
}

func TestValidateSessionSlidesExpiry(t *testing.T) {
	resetState(t)

	token, _ := createSession(nil)

	sessionsMutex.Lock()
	data := sessions[token]
	data.expiry = time.Now().Add(time.Minute) // bien avant le TTL nominal
	sessions[token] = data
	sessionsMutex.Unlock()

	if !validateSession(token) {
		t.Fatal("session jugée invalide alors qu'elle est encore valide")
	}

	sessionsMutex.Lock()
	refreshed := sessions[token].expiry
	sessionsMutex.Unlock()

	// L'expiration doit avoir été repoussée d'un TTL complet (timeout
	// d'inactivité, et non durée de vie absolue).
	if time.Until(refreshed) < sessionTTL-time.Minute {
		t.Fatalf("expiration non prolongée : reste %s", time.Until(refreshed))
	}
}

func TestInvalidateSession(t *testing.T) {
	resetState(t)

	token, _ := createSession(nil)
	invalidateSession(token)

	if validateSession(token) {
		t.Fatal("la session est encore valide après déconnexion")
	}
}

func TestInvalidateSessionDropsVaultKey(t *testing.T) {
	resetState(t)

	token, _ := createSession([]byte("clé-secrète-de-coffre"))
	invalidateSession(token)

	// La clé du coffre ne doit pas survivre à la déconnexion.
	if _, _, err := vaultKeysFor(token); err == nil {
		t.Fatal("la clé de coffre est encore accessible après déconnexion")
	}
}

func TestCSRFValidation(t *testing.T) {
	resetState(t)

	token, csrf := createSession(nil)

	if !validCSRF(token, csrf) {
		t.Fatal("le jeton CSRF légitime est refusé")
	}
	if validCSRF(token, "mauvais-jeton") {
		t.Fatal("un jeton CSRF incorrect est accepté")
	}
	if validCSRF(token, "") {
		t.Fatal("un jeton CSRF vide est accepté")
	}
	if validCSRF("session-inconnue", csrf) {
		t.Fatal("un jeton CSRF est accepté pour une session inconnue")
	}
}

func TestCSRFTokensDifferPerSession(t *testing.T) {
	resetState(t)

	tokenA, csrfA := createSession(nil)
	_, csrfB := createSession(nil)

	if csrfA == csrfB {
		t.Fatal("deux sessions partagent le même jeton CSRF")
	}
	// Le jeton d'une session ne doit pas être valide pour une autre.
	if validCSRF(tokenA, csrfB) {
		t.Fatal("le jeton CSRF d'une autre session est accepté")
	}
}

func TestRateLimitAfterFailedAttempts(t *testing.T) {
	resetState(t)

	const ip = "192.0.2.10"

	for i := 0; i < maxLoginAttempts; i++ {
		if tooManyLoginAttempts(ip) {
			t.Fatalf("blocage prématuré après %d échecs", i)
		}
		recordFailedLogin(ip)
	}

	if !tooManyLoginAttempts(ip) {
		t.Fatalf("aucun blocage après %d échecs", maxLoginAttempts)
	}
}

func TestRateLimitIsPerIP(t *testing.T) {
	resetState(t)

	for i := 0; i < maxLoginAttempts; i++ {
		recordFailedLogin("192.0.2.10")
	}

	if !tooManyLoginAttempts("192.0.2.10") {
		t.Fatal("l'IP fautive n'est pas bloquée")
	}
	if tooManyLoginAttempts("192.0.2.20") {
		t.Fatal("une autre IP est bloquée par ricochet")
	}
}

func TestRateLimitWindowExpires(t *testing.T) {
	resetState(t)

	const ip = "192.0.2.30"

	// Des échecs plus vieux que la fenêtre ne doivent plus compter.
	old := time.Now().Add(-2 * loginWindow)
	loginAttemptsMutex.Lock()
	for i := 0; i < maxLoginAttempts; i++ {
		loginAttempts[ip] = append(loginAttempts[ip], old)
	}
	loginAttemptsMutex.Unlock()

	if tooManyLoginAttempts(ip) {
		t.Fatal("des tentatives hors fenêtre bloquent encore la connexion")
	}
}

func TestClientIPStripsPort(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.0.2.55:54321"

	if got := clientIP(req); got != "192.0.2.55" {
		t.Fatalf("clientIP() = %q, attendu 192.0.2.55", got)
	}
}
