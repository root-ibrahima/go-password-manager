```
 ██████╗  ██████╗       ██████╗  █████╗ ███████╗███████╗  ███╗   ███╗ ██████╗ ██████╗ 
██╔════╝ ██╔═══██╗      ██╔══██╗██╔══██╗██╔════╝██╔════╝  ████╗ ████║██╔════╝ ██╔══██╗
██║  ███╗██║   ██║█████╗██████╔╝███████║███████╗███████╗  ██╔████╔██║██║  ███╗██████╔╝
██║   ██║██║   ██║╚════╝██╔═══╝ ██╔══██║╚════██║╚════██║  ██║╚██╔╝██║██║   ██║██╔══██╗
╚██████╔╝╚██████╔╝      ██║     ██║  ██║███████║███████║  ██║ ╚═╝ ██║╚██████╔╝██║  ██║
 ╚═════╝  ╚═════╝       ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝  ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝
```

# Go Password Manager

Gestionnaire de mots de passe en Go, avec chiffrement AES-GCM et stockage local
dans une base SQLite chiffrée (SQLCipher).

[![CI](https://github.com/root-ibrahima/go-password-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/root-ibrahima/go-password-manager/actions/workflows/ci.yml)

## Fonctionnalités

- Stockage sécurisé : chiffrement AES-GCM des mots de passe.
- Mot de passe maître : accès restreint avec authentification préalable.
- Interface CLI complète : ajout, listing et récupération des mots de passe.
- Interface web locale : login par mot de passe maître, session expirante, liste et ajout d'entrées.
- Serveur API local : endpoint JSON authentifié par token, prévu pour un client d'auto-remplissage.
- Menu interactif : navigation simplifiée en ligne de commande (promptui).
- Clés sécurisées : fichier `.env` (clé de chiffrement + token API) généré automatiquement au démarrage.
- Générateur de mots de passe : `crypto/rand` avec rejet d'échantillonnage (pas de biais modulo),
  côté serveur comme côté navigateur.

## Architecture du projet

```txt
go-password-manager/
├── cmd/                  Commandes CLI (cobra)
│   ├── root.go           Commande racine
│   ├── add.go            Ajouter un mot de passe
│   ├── list.go           Lister les mots de passe
│   ├── get.go            Récupérer un mot de passe
│   ├── setmaster.go      Définir le mot de passe maître
│   ├── api.go            Serveur API local (endpoint JSON)
│   ├── web.go            Démarrage de l'interface web
│   └── tui.go            Menu interactif
├── internal/
│   ├── crypto/           Chiffrement AES-GCM, hashage bcrypt, génération de mots de passe
│   │   └── crypto_test.go  Tests unitaires (chiffrement, hash, génération)
│   └── storage/          Base SQLite chiffrée (SQLCipher) et gestion du .env
├── web/                  Interface web (gorilla/mux + html/template + CSS maison)
│   ├── auth.go           Sessions, CSRF et limitation des tentatives de login
│   ├── server.go         Routes, handlers et en-têtes de sécurité
│   ├── templates/        base.html + pages (accueil, coffre, ajout)
│   └── static/           app.css, app.js, theme.js, favicon, polices auto-hébergées
├── main.go               Point d'entrée du programme
├── Dockerfile            Image de build/exécution (multi-stage, non-root)
├── .golangci.yml         Configuration du linter
├── SECURITY.md           Politique de signalement et limites du modèle de menace
└── .github/
    ├── workflows/        Intégration continue (build, lint, govulncheck, gitleaks)
    └── dependabot.yml    Mises à jour hebdomadaires des dépendances
```

## Installation et configuration

### 1. Cloner le projet

```sh
git clone https://github.com/root-ibrahima/go-password-manager.git
cd go-password-manager
```

### 2. Installer les dépendances

Le projet utilise `go-sqlcipher`, qui nécessite CGO et les en-têtes SQLCipher :

```sh
sudo apt-get install libsqlcipher-dev   # Debian/Ubuntu
go mod download
```

### 3. Définir le mot de passe maître (obligatoire)

Le fichier `.env` (clé de chiffrement + token API) est généré automatiquement
au premier lancement s'il est absent. En revanche, le mot de passe maître doit
être défini explicitement : **sans lui, aucune commande ni l'interface web ne
donnent accès au coffre.**

```sh
go run main.go set-master
```

### 4. Lancer le gestionnaire de mots de passe

```sh
go run main.go menu   # menu interactif
go run main.go web    # interface web sur http://localhost:8080
```

## Utilisation des commandes CLI

### Définir ou changer le mot de passe maître

```sh
go run main.go set-master
```

### Ajouter un mot de passe

```sh
go run main.go add
```

### Lister les mots de passe

```sh
go run main.go list
```

### Récupérer un mot de passe en clair

```sh
go run main.go get
```

### Démarrer l'API locale

```sh
go run main.go api
```

Expose `POST /get-password` sur `http://localhost:8080` : la requête fournit un
site et le `API_TOKEN` du `.env`, la réponse renvoie l'identifiant et le mot de
passe déchiffré. Cet endpoint était consommé par une extension navigateur
prototype, qui ne fait plus partie du dépôt.

L'API et l'interface web écoutent toutes deux sur le port `8080` : les deux
commandes ne peuvent pas tourner simultanément en l'état.

### Démarrer l'interface web

```sh
go run main.go web
```

## Interface web

Servie sur `http://localhost:8080` par `net/http` + `gorilla/mux`, rendue avec
`html/template`. Routes : `/` (accueil), `/login`, `/logout`, `/passwords`
(coffre) et `/add-password`. Les deux dernières exigent une session valide.

Le front est écrit à la main, sans framework ni dépendance externe :

- **Aucune requête tierce.** Polices, CSS et JS sont auto-hébergés, ce qui est
  imposé par la CSP (`default-src 'self'`) et évite toute fuite vers un CDN.
- **Amélioration progressive.** Sans JavaScript, les formulaires HTML natifs
  restent pleinement fonctionnels ; le JS n'ajoute que du confort.
- **Thème clair et sombre**, avec bascule mémorisée (`localStorage`) et respect
  de `prefers-color-scheme` par défaut.
- **Aide à la saisie** : jauge de robustesse calculée en bits d'entropie
  (longueur × log₂ de l'alphabet), générateur navigateur basé sur
  `crypto.getRandomValues`, affichage/masquage et copie de l'identifiant.
- **Accessibilité** : navigation clavier, `aria-label` sur les contrôles
  iconographiques, lien d'évitement, et animations désactivées sous
  `prefers-reduced-motion`.

## Docker

```sh
docker build -t go-password-manager .
docker run -d --name go-password-manager -p 8080:8080 \
  -v go-password-manager-data:/app go-password-manager

# Étape obligatoire au premier démarrage (prompt interactif) :
docker exec -it go-password-manager ./go-password-manager set-master
```

L'image lance l'interface web par défaut. Passez une autre commande en argument
(`add`, `list`, `get`, `menu`, ...) pour utiliser le CLI dans le conteneur.

Le volume monté sur `/app` conserve `passwords.db` et `.env` entre deux
redémarrages : sans lui, le coffre est perdu à chaque recréation du conteneur.

## Intégration continue

Le workflow GitHub Actions (`.github/workflows/ci.yml`) exécute à chaque push
et pull request sur `main`, en quatre jobs indépendants :

- **build** : `go vet`, `go test`, `go build`.
- **govulncheck** : vulnérabilités connues atteignables dans le code et ses dépendances.
- **lint** : `golangci-lint` (`errcheck`, `staticcheck`, `unused`, `gosec`).
- **gitleaks** : scan de secrets sur l'historique complet du dépôt.

Dependabot (`.github/dependabot.yml`) tient à jour les dépendances Go, l'image
Docker et les actions GitHub chaque semaine.

### Reproduire la CI en local

```sh
go test ./...        # tests unitaires (paquet crypto)
go vet ./...
golangci-lint run    # config dans .golangci.yml
govulncheck ./...
```

## Sécurité et bonnes pratiques

- Chiffrement AES-GCM pour garantir la sécurité des mots de passe.
- Mot de passe maître stocké en hash (bcrypt), jamais en clair.
- Base de données SQLite chiffrée avec SQLCipher, dont la passphrase est `ENCRYPTION_KEY` (jamais codée en dur).
- Interface web protégée par une session serveur (cookie `HttpOnly`, timeout d'inactivité 15 min) et un jeton CSRF sur le formulaire d'ajout.
- Limitation du nombre de tentatives de connexion par IP (5 échecs/minute) sur `/login`.
- En-têtes HTTP de durcissement (CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`).
- Image Docker exécutée par un utilisateur non-root, avec les images de base épinglées par digest.
- Arrêt propre du serveur web sur `SIGTERM`/`SIGINT` (les requêtes en cours ont le temps de se terminer).

Les limites assumées du modèle de menace (clé non dérivée du mot de passe
maître, absence de TLS, pas de limitation de tentatives côté CLI) ainsi que la
procédure de signalement d'une vulnérabilité sont détaillées dans
[SECURITY.md](SECURITY.md).

## Sauvegarde et restauration

`passwords.db` est le fichier SQLCipher qui contient toutes les entrées ; `.env`
contient `ENCRYPTION_KEY`, indispensable pour déchiffrer les mots de passe qu'il
contient. **Une sauvegarde de `passwords.db` sans `.env` est inutilisable, et
inversement.** Les deux doivent être sauvegardés ensemble, et le `.env` protégé
au moins aussi bien que la base elle-même (il est en clair, permissions `0600`).

Sauvegarde à froid (serveur/CLI arrêté, pas d'écriture concurrente) :

```sh
cp passwords.db .env /chemin/vers/sauvegarde/
```

Restauration : replacer les deux fichiers dans le répertoire de travail avant de
relancer l'application. Si `ENCRYPTION_KEY` ne correspond plus aux données
présentes dans `passwords.db`, le déchiffrement des mots de passe échouera.

## Contribuer au projet

1. Forker le projet
2. Créer une branche pour une nouvelle fonctionnalité
3. Soumettre une Pull Request

## Licence

Ce projet est sous licence MIT (voir [LICENSE](LICENSE)).

Les polices embarquées dans `web/static/fonts/` sont distribuées sous
[SIL Open Font License 1.1](https://scripts.sil.org/OFL), indépendamment de la
licence du projet :

- **Inter** — © The Inter Project Authors
- **JetBrains Mono** — © The JetBrains Mono Project Authors
