package web

import (
	"context"
	"database/sql"
	"go-password-manager/internal/crypto"
	"go-password-manager/internal/storage"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/gorilla/mux"
)

// pageTemplates associe chaque page à son propre gabarit (base.html + la page).
// Chaque page définit un bloc "content" du même nom : les compiler par paire
// évite qu'ils s'écrasent les uns les autres dans un unique jeu de templates.
var pageTemplates = make(map[string]*template.Template)

// InitTemplates charge les templates au démarrage
func InitTemplates() {
	for _, page := range []string{"home.html", "list.html", "add.html", "generator.html"} {
		tmpl, err := template.ParseFiles("web/templates/base.html", "web/templates/"+page)
		if err != nil {
			slog.Error("erreur de chargement des templates", "page", page, "error", err)
			os.Exit(1)
		}
		pageTemplates[page] = tmpl
	}
	slog.Info("templates chargés avec succès")
}

// HomeHandler affiche la page d'accueil
func HomeHandler(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, "home.html", nil)
}

// GeneratorHandler affiche le générateur de mots de passe.
func GeneratorHandler(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, "generator.html", nil)
}

// passwordEntry est une entrée affichée dans la liste des mots de passe.
type passwordEntry struct {
	ID       int
	Site     string
	Username string
}

// listPageData porte les données affichées par list.html.
type listPageData struct {
	Passwords []passwordEntry
	Added     string
	Deleted   string
	Error     string
	CSRFToken string
}

// openVault ouvre la base avec les clés de la session en cours.
func openVault(r *http.Request) (*sql.DB, []byte, error) {
	dataKey, dbKey, err := vaultKeysFor(sessionTokenFromRequest(r))
	if err != nil {
		return nil, nil, err
	}

	db, err := storage.InitDB(dbKey)
	if err != nil {
		return nil, nil, err
	}
	return db, dataKey, nil
}

// ListPasswords affiche la liste des mots de passe
func ListPasswords(w http.ResponseWriter, r *http.Request) {
	db, _, err := openVault(r)
	if err != nil {
		slog.Error("ouverture du coffre", "error", err)
		http.Error(w, "Erreur serveur", http.StatusInternalServerError)
		return
	}
	defer func() { _ = db.Close() }()

	entries, err := storage.ListEntries(db)
	if err != nil {
		http.Error(w, "Erreur lors de la récupération des mots de passe", http.StatusInternalServerError)
		return
	}

	passwords := make([]passwordEntry, 0, len(entries))
	for _, e := range entries {
		passwords = append(passwords, passwordEntry{ID: e.ID, Site: e.Site, Username: e.Username})
	}

	renderTemplate(w, "list.html", listPageData{
		Passwords: passwords,
		Added:     r.URL.Query().Get("added"),
		Deleted:   r.URL.Query().Get("deleted"),
		CSRFToken: csrfTokenFor(sessionTokenFromRequest(r)),
	})
}

// addPageData porte les données affichées par add.html.
type addPageData struct {
	Error     string
	CSRFToken string
}

// AddPasswordHandler gère l'ajout d'un mot de passe
func AddPasswordHandler(w http.ResponseWriter, r *http.Request) {
	csrfToken := csrfTokenFor(sessionTokenFromRequest(r))

	if r.Method != http.MethodPost {
		renderTemplate(w, "add.html", addPageData{CSRFToken: csrfToken})
		return
	}

	fail := func(message string) {
		renderTemplate(w, "add.html", addPageData{Error: message, CSRFToken: csrfToken})
	}

	if !validCSRF(sessionTokenFromRequest(r), r.FormValue("csrf_token")) {
		fail("Session invalide, veuillez réessayer.")
		return
	}

	site := r.FormValue("site")
	username := r.FormValue("username")
	password := r.FormValue("password")

	if site == "" || username == "" {
		fail("Le site et le nom d'utilisateur sont obligatoires.")
		return
	}

	db, dataKey, err := openVault(r)
	if err != nil {
		slog.Error("ouverture du coffre", "error", err)
		fail("Erreur serveur.")
		return
	}
	defer func() { _ = db.Close() }()

	if password == "" {
		password = crypto.GeneratePassword(16)
	}

	encryptedPassword, err := crypto.Encrypt(password, dataKey)
	if err != nil {
		fail("Erreur de chiffrement du mot de passe.")
		return
	}

	if err := storage.AddEntry(db, site, username, encryptedPassword); err != nil {
		fail("Erreur lors de l'enregistrement.")
		return
	}

	// Le préfixe est littéral, donc pas de redirection ouverte possible ; site
	// est échappé pour éviter l'injection d'un paramètre supplémentaire.
	http.Redirect(w, r, "/passwords?added="+url.QueryEscape(site), http.StatusSeeOther)
}

// DeletePasswordHandler supprime une entrée du coffre.
func DeletePasswordHandler(w http.ResponseWriter, r *http.Request) {
	if !validCSRF(sessionTokenFromRequest(r), r.FormValue("csrf_token")) {
		http.Redirect(w, r, "/passwords", http.StatusSeeOther)
		return
	}

	id, err := strconv.Atoi(r.FormValue("id"))
	if err != nil {
		http.Redirect(w, r, "/passwords", http.StatusSeeOther)
		return
	}

	db, _, err := openVault(r)
	if err != nil {
		slog.Error("ouverture du coffre", "error", err)
		http.Error(w, "Erreur serveur", http.StatusInternalServerError)
		return
	}
	defer func() { _ = db.Close() }()

	site := r.FormValue("site")
	if err := storage.DeleteEntry(db, id); err != nil {
		slog.Error("suppression d'une entrée", "error", err)
		http.Redirect(w, r, "/passwords", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/passwords?deleted="+url.QueryEscape(site), http.StatusSeeOther)
}

// renderTemplate rend les fichiers HTML
func renderTemplate(w http.ResponseWriter, templateName string, data interface{}) {
	tmpl, ok := pageTemplates[templateName]
	if !ok {
		slog.Error("template inconnu", "template", templateName)
		http.Error(w, "Erreur de rendu", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "base.html", data); err != nil {
		slog.Error("erreur de rendu de template", "template", templateName, "error", err)
		http.Error(w, "Erreur de rendu", http.StatusInternalServerError)
	}
}

// securityHeaders ajoute les en-têtes HTTP de durcissement de base à chaque réponse.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		// style-src autorise 'unsafe-inline' pour les attributs style="" utilisés
		// dans quelques réponses HTML ; script-src reste strict ('self' uniquement,
		// aucun script inline nulle part), ce qui couvre le risque XSS principal.
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "+
				"img-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// statusRecorder capture le code de statut pour le journal d'accès.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (rec *statusRecorder) WriteHeader(code int) {
	rec.status = code
	rec.ResponseWriter.WriteHeader(code)
}

// accessLog journalise chaque requête en JSON structuré. Aucune donnée
// sensible n'est enregistrée : ni corps de requête, ni paramètres.
func accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(rec, r)

		slog.Info("requête",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

// StartServer démarre le serveur web
func StartServer() {
	InitTemplates()       // Charger les templates au démarrage
	startSessionCleanup() // Purger périodiquement les sessions expirées

	r := mux.NewRouter()
	r.Use(accessLog)
	r.Use(securityHeaders)
	r.HandleFunc("/", HomeHandler)
	r.HandleFunc("/login", LoginHandler).Methods("GET", "POST")
	r.HandleFunc("/logout", LogoutHandler).Methods("GET", "POST")
	r.HandleFunc("/generator", requireAuth(GeneratorHandler)).Methods("GET")
	r.HandleFunc("/passwords", requireAuth(ListPasswords)).Methods("GET")
	r.HandleFunc("/add-password", requireAuth(AddPasswordHandler)).Methods("GET", "POST")
	r.HandleFunc("/delete-password", requireAuth(DeletePasswordHandler)).Methods("POST")

	// Servir les fichiers statiques
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("web/static"))))

	srv := &http.Server{
		Addr:              ":8080",
		Handler:           r,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		slog.Info("serveur démarré", "url", "http://localhost:8080")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("erreur du serveur", "error", err)
			os.Exit(1)
		}
	}()

	// Arrêt propre sur SIGINT/SIGTERM : on laisse les requêtes en cours se
	// terminer au lieu de les couper brutalement (important en conteneur, où
	// un arrêt/déploiement envoie SIGTERM).
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	slog.Info("arrêt du serveur en cours")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("erreur lors de l'arrêt du serveur", "error", err)
	}
}
