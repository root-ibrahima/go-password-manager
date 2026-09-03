package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// authenticatedRequest construit une requête portant une session valide,
// comme si l'utilisateur venait de se connecter.
func authenticatedRequest(t *testing.T, method, target string, body url.Values) (*http.Request, string) {
	t.Helper()

	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i)
	}
	sessionToken, csrf := createSession(dek)

	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, target, strings.NewReader(body.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	//nolint:gosec // G124: cookie de requête côté client ; Secure/HttpOnly sont
	// des attributs de réponse, sans objet ici.
	req.AddCookie(&http.Cookie{Name: "session_token", Value: sessionToken})

	return req, csrf
}

func TestRequireAuthRedirectsWithoutSession(t *testing.T) {
	resetState(t)

	called := false
	handler := requireAuth(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	rec := httptest.NewRecorder()
	handler(rec, httptest.NewRequest("GET", "/passwords", nil))

	if called {
		t.Fatal("le handler protégé a été exécuté sans session")
	}
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("statut = %d, attendu %d", rec.Code, http.StatusSeeOther)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Fatalf("redirection vers %q, attendu /login", loc)
	}
}

func TestRequireAuthRejectsUnknownCookie(t *testing.T) {
	resetState(t)

	called := false
	handler := requireAuth(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	req := httptest.NewRequest("GET", "/passwords", nil)
	//nolint:gosec // G124: cookie de requête côté client, voir ci-dessus.
	req.AddCookie(&http.Cookie{Name: "session_token", Value: "jeton-fabriqué"})

	rec := httptest.NewRecorder()
	handler(rec, req)

	if called {
		t.Fatal("un cookie de session forgé a été accepté")
	}
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("statut = %d, attendu une redirection", rec.Code)
	}
}

func TestRequireAuthPassesWithValidSession(t *testing.T) {
	resetState(t)

	var seenToken string
	handler := requireAuth(func(w http.ResponseWriter, r *http.Request) {
		seenToken = sessionTokenFromRequest(r)
		w.WriteHeader(http.StatusOK)
	})

	req, _ := authenticatedRequest(t, "GET", "/passwords", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("statut = %d, attendu 200", rec.Code)
	}
	// Le middleware doit propager le jeton pour que le handler puisse
	// retrouver la clé du coffre et le jeton CSRF.
	if seenToken == "" {
		t.Fatal("le jeton de session n'a pas été propagé dans le contexte")
	}
}

func TestDeleteRejectsInvalidCSRF(t *testing.T) {
	resetState(t)

	form := url.Values{"id": {"1"}, "csrf_token": {"jeton-invalide"}}
	req, _ := authenticatedRequest(t, "POST", "/delete-password", form)

	rec := httptest.NewRecorder()
	DeletePasswordHandler(rec, req)

	// Sans CSRF valide, on repart vers la liste sans rien supprimer.
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("statut = %d, attendu %d", rec.Code, http.StatusSeeOther)
	}
	if loc := rec.Header().Get("Location"); loc != "/passwords" {
		t.Fatalf("redirection vers %q, attendu /passwords", loc)
	}
}

func TestSecurityHeadersArePresent(t *testing.T) {
	handler := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))

	expected := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	}
	for header, want := range expected {
		if got := rec.Header().Get(header); got != want {
			t.Errorf("%s = %q, attendu %q", header, got, want)
		}
	}

	csp := rec.Header().Get("Content-Security-Policy")
	for _, directive := range []string{"default-src 'self'", "script-src 'self'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, directive) {
			t.Errorf("CSP ne contient pas %q : %s", directive, csp)
		}
	}
}

func TestAccessLogPreservesStatus(t *testing.T) {
	handler := accessLog(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))

	if rec.Code != http.StatusTeapot {
		t.Fatalf("statut = %d, le middleware de log altère la réponse", rec.Code)
	}
}

func TestLogoutClearsCookieAndSession(t *testing.T) {
	resetState(t)

	req, _ := authenticatedRequest(t, "GET", "/logout", nil)
	cookie, err := req.Cookie("session_token")
	if err != nil {
		t.Fatalf("cookie absent de la requête de test : %v", err)
	}

	rec := httptest.NewRecorder()
	LogoutHandler(rec, req)

	if validateSession(cookie.Value) {
		t.Fatal("la session est encore valide après /logout")
	}

	setCookie := rec.Header().Get("Set-Cookie")
	if !strings.Contains(setCookie, "session_token=;") {
		t.Fatalf("le cookie n'est pas vidé : %q", setCookie)
	}
	if !strings.Contains(setCookie, "Max-Age=0") {
		t.Fatalf("le cookie n'est pas expiré : %q", setCookie)
	}
}
