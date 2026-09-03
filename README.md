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
│   ├── crypto/           Chiffrement AES-GCM et hashage du mot de passe maître
│   └── storage/          Base SQLite chiffrée (SQLCipher) et gestion du .env
├── web/                  Interface web (gorilla/mux + html/template + CSS maison)
│   ├── auth.go           Sessions, CSRF et limitation des tentatives de login
│   └── server.go         Routes, handlers et en-têtes de sécurité
├── main.go               Point d'entrée du programme
├── Dockerfile            Image de build/exécution
└── .github/workflows/    Intégration continue (build, lint, govulncheck, gitleaks)
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

### 3. Lancer le gestionnaire de mots de passe

Le fichier `.env` (clé de chiffrement + token API) est généré automatiquement
au premier lancement s'il est absent.

```sh
go run main.go menu
```

## Utilisation des commandes CLI

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

## Docker

```sh
docker build -t go-password-manager .
docker run -p 8080:8080 -v go-password-manager-data:/app go-password-manager
```

L'image lance l'interface web par défaut. Passez une autre commande en argument
(`add`, `list`, `get`, `menu`, ...) pour utiliser le CLI dans le conteneur.

## Intégration continue

Le workflow GitHub Actions (`.github/workflows/ci.yml`) exécute à chaque push
et pull request sur `main`, en quatre jobs indépendants :

- **build** : `go vet`, `go test`, `go build`.
- **govulncheck** : vulnérabilités connues atteignables dans le code et ses dépendances.
- **lint** : `golangci-lint` (`errcheck`, `staticcheck`, `unused`, `gosec`).
- **gitleaks** : scan de secrets sur l'historique complet du dépôt.

Dependabot (`.github/dependabot.yml`) tient à jour les dépendances Go, l'image
Docker et les actions GitHub chaque semaine.

## Sécurité et bonnes pratiques

- Chiffrement AES-GCM pour garantir la sécurité des mots de passe.
- Mot de passe maître stocké en hash (bcrypt), jamais en clair.
- Base de données SQLite chiffrée avec SQLCipher, clé dérivée de `ENCRYPTION_KEY` (jamais hardcodée).
- Interface web protégée par une session serveur (cookie `HttpOnly`, timeout d'inactivité 15 min) et un jeton CSRF sur le formulaire d'ajout.
- Limitation du nombre de tentatives de connexion par IP (5 échecs/minute) sur `/login`.
- En-têtes HTTP de durcissement (CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`).
- Image Docker exécutée par un utilisateur non-root, avec les images de base épinglées par digest.
- Arrêt propre du serveur web sur `SIGTERM`/`SIGINT` (les requêtes en cours ont le temps de se terminer).

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

Ce projet est sous licence MIT.
