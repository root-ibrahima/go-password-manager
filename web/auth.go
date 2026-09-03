package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"go-password-manager/internal/storage"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

// sessionTTL est la durée d'inactivité tolérée avant expiration d'une session.
const sessionTTL = 15 * time.Minute

// sessionData associe à un jeton de session sa date d'expiration et le jeton
// CSRF (double-submit) émis pour cette session.
type sessionData struct {
	expiry    time.Time
	csrfToken string
}

var (
	sessions      = make(map[string]sessionData)
	sessionsMutex sync.Mutex
)

// maxLoginAttempts est le nombre d'échecs autorisés par IP sur loginWindow
// avant blocage temporaire, pour limiter le bruteforce du mot de passe maître.
const (
	maxLoginAttempts = 5
	loginWindow      = time.Minute
)

// loginAttempts associe une IP à l'horodatage de ses tentatives échouées récentes.
var (
	loginAttempts      = make(map[string][]time.Time)
	loginAttemptsMutex sync.Mutex
)

// clientIP extrait l'adresse IP (sans le port) de la requête.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// tooManyLoginAttempts indique si l'IP a atteint la limite d'échecs récents.
func tooManyLoginAttempts(ip string) bool {
	now := time.Now()
	loginAttemptsMutex.Lock()
	defer loginAttemptsMutex.Unlock()

	var recent []time.Time
	for _, t := range loginAttempts[ip] {
		if now.Sub(t) < loginWindow {
			recent = append(recent, t)
		}
	}
	loginAttempts[ip] = recent

	return len(recent) >= maxLoginAttempts
}

// recordFailedLogin enregistre un échec d'authentification pour l'IP donnée.
func recordFailedLogin(ip string) {
	loginAttemptsMutex.Lock()
	defer loginAttemptsMutex.Unlock()
	loginAttempts[ip] = append(loginAttempts[ip], time.Now())
}

// cleanupOnce garantit qu'un seul goroutine de purge des sessions expirées
// est démarré, même si startSessionCleanup est appelée plusieurs fois.
var cleanupOnce sync.Once

// startSessionCleanup démarre un nettoyage périodique des sessions expirées
// pour que la map ne grossisse pas indéfiniment sur un serveur longue durée.
func startSessionCleanup() {
	cleanupOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(5 * time.Minute)
			defer ticker.Stop()
			for range ticker.C {
				now := time.Now()

				sessionsMutex.Lock()
				for token, data := range sessions {
					if now.After(data.expiry) {
						delete(sessions, token)
					}
				}
				sessionsMutex.Unlock()

				loginAttemptsMutex.Lock()
				for ip, attempts := range loginAttempts {
					var recent []time.Time
					for _, t := range attempts {
						if now.Sub(t) < loginWindow {
							recent = append(recent, t)
						}
					}
					if len(recent) == 0 {
						delete(loginAttempts, ip)
					} else {
						loginAttempts[ip] = recent
					}
				}
				loginAttemptsMutex.Unlock()
			}
		}()
	})
}

// randomToken génère un jeton aléatoire de 32 octets encodé en hexadécimal.
func randomToken() string {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		// crypto/rand ne devrait jamais échouer ; on ne peut pas créer de jeton sûr sinon.
		panic("impossible de générer un jeton sécurisé : " + err.Error())
	}
	return hex.EncodeToString(tokenBytes)
}

// createSession génère un nouveau jeton de session et son jeton CSRF associé,
// et les enregistre avec une expiration glissante de 15 minutes.
func createSession() (sessionToken, csrfToken string) {
	sessionToken = randomToken()
	csrfToken = randomToken()

	sessionsMutex.Lock()
	sessions[sessionToken] = sessionData{expiry: time.Now().Add(sessionTTL), csrfToken: csrfToken}
	sessionsMutex.Unlock()

	return sessionToken, csrfToken
}

// validateSession vérifie qu'un jeton de session est connu et non expiré.
// Si valide, l'expiration est prolongée de 15 minutes (timeout d'inactivité).
func validateSession(token string) bool {
	if token == "" {
		return false
	}

	sessionsMutex.Lock()
	defer sessionsMutex.Unlock()

	data, ok := sessions[token]
	if !ok || time.Now().After(data.expiry) {
		return false
	}

	data.expiry = time.Now().Add(sessionTTL)
	sessions[token] = data
	return true
}

// csrfTokenFor renvoie le jeton CSRF associé à une session, ou "" si inconnue.
func csrfTokenFor(sessionToken string) string {
	sessionsMutex.Lock()
	defer sessionsMutex.Unlock()
	return sessions[sessionToken].csrfToken
}

// validCSRF vérifie en temps constant le jeton CSRF soumis par un formulaire
// contre celui attendu pour la session (protection en profondeur : SameSite=Lax
// bloque déjà l'essentiel des soumissions cross-site, mais un jeton explicite
// est la pratique standard dès lors qu'un cookie de session existe).
func validCSRF(sessionToken, submitted string) bool {
	expected := csrfTokenFor(sessionToken)
	if expected == "" || submitted == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(submitted)) == 1
}

// invalidateSession supprime immédiatement une session côté serveur (déconnexion).
func invalidateSession(token string) {
	sessionsMutex.Lock()
	delete(sessions, token)
	sessionsMutex.Unlock()
}

const loginFormHTML = `<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="color-scheme" content="dark light">
    <title>Connexion — SecurePass</title>

    <link rel="icon" href="/static/favicon.svg" type="image/svg+xml">
    <link rel="preload" href="/static/fonts/inter-var-latin.woff2" as="font" type="font/woff2" crossorigin>
    <link rel="stylesheet" href="/static/app.css">

    <script src="/static/theme.js"></script>
</head>
<body>
    <div class="grid-overlay" aria-hidden="true"></div>

    <div class="auth-shell">
        <button type="button" class="theme-toggle" data-theme-toggle aria-label="Changer de thème">
            <svg class="icon icon-moon" viewBox="0 0 24 24" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"></path></svg>
            <svg class="icon icon-sun" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4"></circle><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"></path></svg>
        </button>

        <main class="auth-card">
            <div class="vault">
                <svg viewBox="0 0 24 24" aria-hidden="true">
                    <path class="shackle" d="M8 11V7a4 4 0 0 1 8 0v4"></path>
                    <rect class="lock-body" x="4" y="11" width="16" height="10" rx="2.5"></rect>
                    <circle class="keyhole" cx="12" cy="16" r="1.6"></circle>
                </svg>
            </div>

            <h1>Coffre verrouillé</h1>
            <p class="auth-lede">Entrez votre mot de passe maître pour déverrouiller SecurePass.</p>
            %s
            <form method="POST" action="/login">
                <div class="field">
                    <label for="master_password">
                        <svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M8 11V7a4 4 0 0 1 8 0v4"></path><rect x="4" y="11" width="16" height="10" rx="2.5"></rect></svg>
                        Mot de passe maître
                    </label>
                    <div class="input-wrap">
                        <input type="password" id="master_password" name="master_password"
                               class="mono" autocomplete="current-password" required autofocus>
                        <button type="button" class="icon-btn" data-reveal hidden aria-pressed="false" aria-label="Afficher le mot de passe">
                            <svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                        </button>
                    </div>
                </div>

                <button type="submit" class="btn btn-primary btn-block">
                    <svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M9 12l2 2 4-4"></path><circle cx="12" cy="12" r="10"></circle></svg>
                    Déverrouiller
                </button>
            </form>

            <p class="auth-foot">
                <svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3l7 3v6c0 4.3-2.9 7.8-7 9-4.1-1.2-7-4.7-7-9V6z"></path></svg>
                Session chiffrée · 5 tentatives par minute
            </p>
        </main>
    </div>

    <script src="/static/app.js" defer></script>
</body>
</html>`

const loginErrorAlert = `<div class="alert alert-error" role="alert">
    <svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="10"></circle><path d="M12 8v5M12 16h.01"></path></svg>
    <span>Mot de passe maître incorrect.</span>
</div>`

// LoginHandler affiche le formulaire de connexion (GET) et vérifie le mot de
// passe maître pour ouvrir une session (POST).
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if r.Method != http.MethodPost {
		writeHTML(w, fmt.Sprintf(loginFormHTML, ""))
		return
	}

	ip := clientIP(r)
	if tooManyLoginAttempts(ip) {
		http.Error(w, "Trop de tentatives échouées, réessayez dans une minute.", http.StatusTooManyRequests)
		return
	}

	password := r.FormValue("master_password")

	db, err := storage.InitDB(os.Getenv("ENCRYPTION_KEY"))
	if err != nil {
		slog.Error("erreur d'initialisation de la base de données", "error", err)
		http.Error(w, "Erreur serveur, veuillez réessayer.", http.StatusInternalServerError)
		return
	}
	if !storage.CheckMasterPassword(db, password) {
		recordFailedLogin(ip)
		writeHTML(w, fmt.Sprintf(loginFormHTML, loginErrorAlert))
		return
	}

	sessionToken, _ := createSession()

	//nolint:gosec // G124: Secure est volontairement omis : cet outil est destiné à un usage
	// local/réseau interne servi en HTTP simple, pas parce que c'est acceptable en général.
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Path:     "/",
		MaxAge:   900,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, "/passwords", http.StatusSeeOther)
}

// LogoutHandler invalide la session en cours et efface le cookie associé.
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("session_token"); err == nil {
		invalidateSession(cookie.Value)
	}

	//nolint:gosec // G124: Secure est volontairement omis, voir la justification dans LoginHandler.
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

type sessionCtxKey struct{}

// requireAuth est un middleware qui exige une session valide avant d'exécuter
// le handler protégé, redirigeant vers /login sinon. Le jeton de session est
// propagé via le contexte pour que les handlers protégés puissent en dériver
// le jeton CSRF de la requête (voir csrfTokenFor).
func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_token")
		if err != nil || !validateSession(cookie.Value) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		ctx := context.WithValue(r.Context(), sessionCtxKey{}, cookie.Value)
		next(w, r.WithContext(ctx))
	}
}

// sessionTokenFromRequest récupère le jeton de session déposé dans le contexte
// par requireAuth (chaîne vide si la requête n'est pas passée par ce middleware).
func sessionTokenFromRequest(r *http.Request) string {
	token, _ := r.Context().Value(sessionCtxKey{}).(string)
	return token
}

// writeHTML écrit une réponse HTML en journalisant une éventuelle erreur d'écriture.
func writeHTML(w http.ResponseWriter, body string) {
	if _, err := w.Write([]byte(body)); err != nil {
		slog.Error("erreur d'écriture de la réponse", "error", err)
	}
}
