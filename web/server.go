package web

import (
	"context"
	"go-password-manager/internal/crypto"
	"go-password-manager/internal/storage"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
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
	for _, page := range []string{"home.html", "list.html", "add.html"} {
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

// passwordEntry est une entrée affichée dans la liste des mots de passe.
type passwordEntry struct {
	Site     string
	Username string
}

// listPageData porte les données affichées par list.html.
type listPageData struct {
	Passwords []passwordEntry
	Added     string
}

// ListPasswords affiche la liste des mots de passe
func ListPasswords(w http.ResponseWriter, r *http.Request) {
	db, err := storage.InitDB(os.Getenv("ENCRYPTION_KEY"))
	if err != nil {
		http.Error(w, "Erreur serveur : "+err.Error(), http.StatusInternalServerError)
		return
	}
	rows, err := db.Query("SELECT site, username FROM passwords")
	if err != nil {
		http.Error(w, "Erreur lors de la récupération des mots de passe", http.StatusInternalServerError)
		return
	}
	defer func() { _ = rows.Close() }()

	var passwords []passwordEntry
	for rows.Next() {
		var entry passwordEntry
		if err := rows.Scan(&entry.Site, &entry.Username); err == nil {
			passwords = append(passwords, entry)
		}
	}

	renderTemplate(w, "list.html", listPageData{
		Passwords: passwords,
		Added:     r.URL.Query().Get("added"),
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

	if r.Method == http.MethodPost {
		if !validCSRF(sessionTokenFromRequest(r), r.FormValue("csrf_token")) {
			renderTemplate(w, "add.html", addPageData{Error: "Session invalide, veuillez réessayer.", CSRFToken: csrfToken})
			return
		}

		site := r.FormValue("site")
		username := r.FormValue("username")
		password := r.FormValue("password")

		if site == "" || username == "" {
			renderTemplate(w, "add.html", addPageData{Error: "Le site et le nom d'utilisateur sont obligatoires.", CSRFToken: csrfToken})
			return
		}

		if password == "" {
			password = crypto.GeneratePassword(16)
		}

		encryptionKey := os.Getenv("ENCRYPTION_KEY")
		if len(encryptionKey) != 32 {
			renderTemplate(w, "add.html", addPageData{Error: "Erreur serveur : ENCRYPTION_KEY invalide.", CSRFToken: csrfToken})
			return
		}

		encryptedPassword, err := crypto.Encrypt(password)
		if err != nil {
			renderTemplate(w, "add.html", addPageData{Error: "Erreur de chiffrement du mot de passe.", CSRFToken: csrfToken})
			return
		}

		db, err := storage.InitDB(encryptionKey)
		if err != nil {
			renderTemplate(w, "add.html", addPageData{Error: "Erreur serveur : " + err.Error(), CSRFToken: csrfToken})
			return
		}
		if _, err := db.Exec("INSERT INTO passwords (site, username, password) VALUES (?, ?, ?)", site, username, encryptedPassword); err != nil {
			renderTemplate(w, "add.html", addPageData{Error: "Erreur lors de l'enregistrement.", CSRFToken: csrfToken})
			return
		}

		// Le préfixe "/passwords?added=" est littéral, donc pas de redirection ouverte
		// possible ; site est tout de même échappé pour éviter l'injection d'un
		// paramètre de requête supplémentaire (ex. site="x&added=autre-site").
		http.Redirect(w, r, "/passwords?added="+url.QueryEscape(site), http.StatusSeeOther)
		return
	}

	renderTemplate(w, "add.html", addPageData{CSRFToken: csrfToken})
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
		http.Error(w, "Erreur de rendu : "+err.Error(), http.StatusInternalServerError)
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

// StartServer démarre le serveur web
func StartServer() {
	InitTemplates()       // Charger les templates au démarrage
	startSessionCleanup() // Purger périodiquement les sessions expirées

	r := mux.NewRouter()
	r.Use(securityHeaders)
	r.HandleFunc("/", HomeHandler)
	r.HandleFunc("/login", LoginHandler).Methods("GET", "POST")
	r.HandleFunc("/logout", LogoutHandler).Methods("GET", "POST")
	r.HandleFunc("/passwords", requireAuth(ListPasswords)).Methods("GET")
	r.HandleFunc("/add-password", requireAuth(AddPasswordHandler)).Methods("GET", "POST")

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
