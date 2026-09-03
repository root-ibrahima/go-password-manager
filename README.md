```
 ██████╗  ██████╗       ██████╗  █████╗ ███████╗███████╗  ███╗   ███╗ ██████╗ ██████╗ 
██╔════╝ ██╔═══██╗      ██╔══██╗██╔══██╗██╔════╝██╔════╝  ████╗ ████║██╔════╝ ██╔══██╗
██║  ███╗██║   ██║█████╗██████╔╝███████║███████╗███████╗  ██╔████╔██║██║  ███╗██████╔╝
██║   ██║██║   ██║╚════╝██╔═══╝ ██╔══██║╚════██║╚════██║  ██║╚██╔╝██║██║   ██║██╔══██╗
╚██████╔╝╚██████╔╝      ██║     ██║  ██║███████║███████║  ██║ ╚═╝ ██║╚██████╔╝██║  ██║
 ╚═════╝  ╚═════╝       ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝  ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝
```

# Go Password Manager

Gestionnaire de mots de passe local en Go. La clé de chiffrement est dérivée du
mot de passe maître (Argon2id), les valeurs sont chiffrées en AES-256-GCM et
stockées dans une base SQLite chiffrée (SQLCipher). CLI, menu interactif,
interface web et API locale partagent le même cœur.

[![CI](https://github.com/root-ibrahima/go-password-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/root-ibrahima/go-password-manager/actions/workflows/ci.yml)

## Sommaire

- [Démarrage rapide](#démarrage-rapide)
- [Prérequis](#prérequis)
- [Installation](#installation)
- [Commandes CLI](#commandes-cli)
- [Interface web](#interface-web)
- [API locale](#api-locale)
- [Fonctionnement cryptographique](#fonctionnement-cryptographique)
- [Fichiers créés à l'exécution](#fichiers-créés-à-lexécution)
- [Sauvegarde et restauration](#sauvegarde-et-restauration)
- [Docker](#docker)
- [Développement](#développement)
- [Intégration continue](#intégration-continue)
- [Sécurité](#sécurité)
- [Dépannage](#dépannage)
- [Architecture du projet](#architecture-du-projet)
- [Statut du projet](#statut-du-projet)
- [Licence](#licence)

## Démarrage rapide

Le plus court chemin pour voir l'interface, sans rien installer d'autre que
Docker :

```sh
git clone https://github.com/root-ibrahima/go-password-manager.git
cd go-password-manager
docker compose up -d
docker compose exec securepass ./go-password-manager set-master
```

La dernière commande demande un mot de passe maître (deux fois). Ouvrez ensuite
**<http://localhost:8080>** et connectez-vous avec.

Pour une démonstration reproductible, le mot de passe utilisé dans les captures
et les tests de ce dépôt est :

```
DemoPass123!
```

> **Ce n'est pas un identifiant par défaut** — le projet n'en a aucun, et rien
> n'est préconfiguré : c'est simplement la valeur jetable saisie à l'étape
> `set-master` pour peupler un coffre de démonstration contenant des entrées
> fictives. Choisissez un vrai mot de passe pour un coffre réel : sa robustesse
> est la seule chose qui protège vos données, puisque la clé de chiffrement en
> est dérivée.

Pour repartir d'un coffre vierge :

```sh
docker compose down -v && docker compose up -d
docker compose exec securepass ./go-password-manager set-master
```

## Prérequis

| Besoin | Version | Remarque |
| --- | --- | --- |
| Go | 1.25+ | `go.mod` cible `go 1.25.0` |
| SQLCipher (en-têtes) | — | `libsqlcipher-dev`, requis par `go-sqlcipher` (CGO) |
| Docker | — | uniquement pour la voie conteneurisée |

Le projet impose `CGO_ENABLED=1` : `go-sqlcipher` est un binding C. Une
compilation sans les en-têtes SQLCipher échoue (voir [Dépannage](#dépannage)).

## Installation

### 1. Cloner le projet

```sh
git clone https://github.com/root-ibrahima/go-password-manager.git
cd go-password-manager
```

### 2. Installer les dépendances

```sh
sudo apt-get install libsqlcipher-dev   # Debian/Ubuntu
go mod download
```

### 3. Initialiser le coffre (obligatoire)

Cette étape crée `vault.key` : un sel Argon2id et la clé de données du coffre,
enveloppée par une clé dérivée de votre mot de passe maître. **Sans elle, aucune
commande ni l'interface web ne donnent accès au coffre.**

Le mot de passe maître n'est stocké nulle part : il est redemandé à chaque
utilisation pour reconstituer la clé.

```sh
go run main.go set-master
```

### 4. Lancer

```sh
go run main.go menu   # menu interactif
go run main.go web    # interface web sur http://localhost:8080
```

## Commandes CLI

| Commande | Rôle |
| --- | --- |
| `set-master` | Initialise le coffre, ou change le mot de passe maître s'il existe déjà |
| `add` | Ajoute une entrée (mot de passe généré si le champ est laissé vide) |
| `list` | Liste les entrées, avec affichage en clair sur demande |
| `get` | Affiche l'identifiant et le mot de passe d'un site |
| `delete` | Supprime une entrée, après confirmation |
| `menu` | Menu interactif (promptui) |
| `web` | Démarre l'interface web |
| `api` | Démarre l'API JSON locale |

Toutes les commandes qui touchent au coffre demandent le mot de passe maître.

```sh
go run main.go add
go run main.go list
go run main.go get
go run main.go delete
```

### Changer le mot de passe maître

```sh
go run main.go set-master
```

Sur un coffre existant, la commande demande le mot de passe actuel puis le
nouveau. Seule la clé est ré-enveloppée : les entrées ne sont pas re-chiffrées
et restent lisibles immédiatement.

## Interface web

Servie sur `http://localhost:8080` par `net/http` + `gorilla/mux`, rendue avec
`html/template`.

| Route | Méthode | Authentifiée | Rôle |
| --- | --- | --- | --- |
| `/` | GET | non | Accueil |
| `/login` | GET, POST | non | Déverrouillage du coffre |
| `/logout` | GET, POST | non | Fermeture de session |
| `/passwords` | GET | oui | Coffre : liste des entrées |
| `/add-password` | GET, POST | oui | Ajout d'une entrée |
| `/delete-password` | POST | oui | Suppression (jeton CSRF requis) |
| `/generator` | GET | oui | Générateur de mots de passe |

Le front est écrit à la main, sans framework ni dépendance externe :

- **Aucune requête tierce.** Polices, CSS et JS sont auto-hébergés, ce qui est
  imposé par la CSP (`default-src 'self'`) et évite toute fuite vers un CDN.
- **Amélioration progressive.** Sans JavaScript, les formulaires HTML natifs
  restent pleinement fonctionnels ; le JS n'ajoute que du confort.
- **Thème clair et sombre**, avec bascule mémorisée (`localStorage`) et respect
  de `prefers-color-scheme` par défaut.
- **Aide à la saisie** : jauge de robustesse calculée en bits d'entropie
  (longueur × log₂ de l'alphabet), affichage/masquage et copie de l'identifiant.
- **Générateur dédié** (`/generator`) : longueur de 8 à 64, classes de caractères
  activables, coloration des chiffres et symboles, et garantie d'au moins un
  caractère par classe demandée (un tirage naïf peut n'en produire aucun). Le mot
  de passe généré est transmis au formulaire via `sessionStorage`, jamais par
  l'URL — il ne finit donc ni dans l'historique ni dans les journaux.
- **Suppression protégée** : jeton CSRF et confirmation en deux clics.
- **Accessibilité** : navigation clavier, `aria-label` sur les contrôles
  iconographiques, lien d'évitement, et animations désactivées sous
  `prefers-reduced-motion`.

## API locale

```sh
go run main.go api
```

Le mot de passe maître est demandé **au démarrage** : la clé de déchiffrement
n'existe qu'en mémoire, pour la durée de vie du processus.

Expose `POST /get-password` sur `http://localhost:8080` :

```sh
curl -X POST http://localhost:8080/get-password \
  -H 'Content-Type: application/json' \
  -d '{"site":"github.com","auth":"<API_TOKEN du .env>"}'
```

La réponse renvoie l'identifiant et le mot de passe déchiffré. Cet endpoint était
consommé par une extension navigateur prototype, qui ne fait plus partie du
dépôt.

> L'API et l'interface web écoutent toutes deux sur le port `8080` : les deux
> commandes ne peuvent pas tourner simultanément en l'état.

## Fonctionnement cryptographique

Le mot de passe maître ne chiffre jamais directement les données. Il sert à
déballer une clé de données aléatoire, elle-même à l'origine de deux sous-clés
d'usage :

```txt
   mot de passe maître  (jamais stocké, jamais haché)
            │
            │  Argon2id — 64 Mio, 3 passes, 4 voies, sel dans vault.key
            ▼
           KEK  ──────── ouvre (AES-256-GCM) ────────┐
                                                     │
                          vault.key : clé de données enveloppée
                                                     │
                                                     ▼
                           DEK — 32 octets aléatoires, jamais écrits en clair
                                                     │
                        ┌────────── HKDF-SHA256 ─────┴──────────┐
                        ▼                                        ▼
                sous-clé « data »                        sous-clé « db »
        AES-256-GCM des mots de passe              passphrase SQLCipher
```

Trois conséquences pratiques :

1. **Aucune clé exploitable au repos.** `vault.key` ne contient qu'un sel et une
   clé chiffrée ; sans le mot de passe maître, il est inerte.
2. **Changer le mot de passe maître est instantané.** Seule la DEK est
   ré-enveloppée — les entrées ne sont pas re-chiffrées. C'est la raison du choix
   de l'enveloppement plutôt que d'une dérivation directe, qui aurait rendu
   illisibles les données existantes à chaque changement.
3. **Un mauvais mot de passe est détecté par le déchiffrement lui-même.**
   L'ouverture AES-GCM de la clé enveloppée échoue : il faut réellement pouvoir
   déchiffrer, pas seulement connaître une valeur correspondant à un hash.

## Fichiers créés à l'exécution

Créés dans le répertoire de travail, tous ignorés par Git :

| Fichier | Permissions | Contenu | Perte = ? |
| --- | --- | --- | --- |
| `vault.key` | `0600` | Sel Argon2id + clé de données enveloppée | **Coffre irrécupérable** |
| `passwords.db` | `0600` | Entrées chiffrées (SQLCipher) | **Données perdues** |
| `.env` | `0600` | `API_TOKEN` uniquement | Régénéré automatiquement |

## Sauvegarde et restauration

Deux fichiers sont indispensables et doivent être sauvegardés **ensemble** :
`passwords.db` et `vault.key`.

**Une sauvegarde de `passwords.db` sans `vault.key` est définitivement
irrécupérable**, même en connaissant le mot de passe maître : la clé de données
est aléatoire et n'existe nulle part ailleurs. L'inverse est vrai aussi.

`vault.key` ne contient rien d'exploitable sans le mot de passe maître, ce qui
rend la sauvegarde nettement moins sensible qu'avec une clé en clair — mais elle
reste à protéger : sa possession ramène l'attaquant à une attaque par
dictionnaire sur votre mot de passe maître, freinée par Argon2id.

Sauvegarde à froid (serveur/CLI arrêté, pas d'écriture concurrente) :

```sh
cp passwords.db vault.key /chemin/vers/sauvegarde/
```

Restauration : replacer les deux fichiers dans le répertoire de travail, puis
relancer l'application et saisir le mot de passe maître d'origine.

## Docker

```sh
docker compose up -d
docker compose exec securepass ./go-password-manager set-master
```

Ou sans Compose :

```sh
docker build -t go-password-manager .
docker run -d --name go-password-manager -p 8080:8080 \
  -v go-password-manager-data:/app go-password-manager
docker exec -it go-password-manager ./go-password-manager set-master
```

L'image lance l'interface web par défaut. Passez une autre commande en argument
(`add`, `list`, `get`, `delete`, `menu`, ...) pour utiliser le CLI dans le
conteneur.

Le volume monté sur `/app` conserve `vault.key`, `passwords.db` et `.env` entre
deux redémarrages : **sans lui, le coffre est perdu à chaque recréation du
conteneur.**

Commandes utiles :

```sh
docker compose logs -f securepass   # journal d'accès structuré (JSON)
docker compose down                 # arrêter, volume conservé
docker compose down -v              # arrêter et effacer le coffre
```

L'image est multi-stage, les images de base sont épinglées par digest, et le
conteneur tourne en utilisateur non-root (`appuser`) sans capacité Linux.

## Développement

```sh
go test ./...                 # 47 tests (crypto, storage, handlers HTTP)
go test ./... -cover          # couverture par paquet
go vet ./...
golangci-lint run             # config dans .golangci.yml
govulncheck ./...
```

Les tests couvrent notamment l'enveloppement et le déballage de clé, la
dépendance au sel, la séparation des sous-clés, le renouvellement du nonce GCM,
la détection d'altération, les permissions des fichiers, le fait que la base
soit illisible avec une mauvaise clé, le cycle de vie des sessions, la
validation CSRF, la limitation des tentatives et la barrière d'authentification
(via `httptest`).

Aucun outil n'est nécessaire en local : tout tourne aussi dans un conteneur Go
avec `libsqlcipher-dev`, à l'identique de la CI.

## Intégration continue

Le workflow GitHub Actions (`.github/workflows/ci.yml`) s'exécute à chaque push
et pull request sur `main`, en quatre jobs indépendants :

- **build** : `go vet`, `go test`, `go build`.
- **govulncheck** : vulnérabilités connues atteignables dans le code et ses dépendances.
- **lint** : `golangci-lint` (`errcheck`, `staticcheck`, `unused`, `gosec`).
- **gitleaks** : scan de secrets sur l'historique complet du dépôt.

Dependabot (`.github/dependabot.yml`) tient à jour les dépendances Go, l'image
Docker et les actions GitHub chaque semaine.

## Sécurité

- **Clé dérivée du mot de passe maître** via Argon2id (64 Mio, 3 passes, 4 voies —
  option interactive de la RFC 9106). Le mot de passe maître n'est stocké nulle part.
- **Enveloppement de clé** : la clé de données aléatoire est chiffrée par la clé
  dérivée et conservée dans `vault.key`.
- **Séparation des usages** : deux sous-clés distinctes dérivées par HKDF-SHA256,
  l'une pour le chiffrement des valeurs, l'autre pour SQLCipher.
- Chiffrement AES-256-GCM (authentifié) des mots de passe, nonce aléatoire par entrée.
- `vault.key` et `passwords.db` en permissions `0600`.
- Session serveur (cookie `HttpOnly`, `SameSite=Lax`, timeout d'inactivité de
  15 minutes) ; la clé du coffre ne vit qu'en mémoire et disparaît à la déconnexion.
- Jeton CSRF lié à la session sur les formulaires d'ajout et de suppression.
- Limitation des tentatives de connexion par IP (5 échecs par minute) sur `/login`.
- Comparaisons de secrets en temps constant (`crypto/subtle`).
- En-têtes de durcissement : CSP, `X-Frame-Options`, `X-Content-Type-Options`,
  `Referrer-Policy`.
- Arrêt propre sur `SIGTERM`/`SIGINT` : les requêtes en cours ont le temps de se terminer.

Les limites assumées du modèle de menace (absence de TLS, mémoire du processus
non verrouillée, pas de limitation de tentatives côté CLI) ainsi que la procédure
de signalement d'une vulnérabilité sont détaillées dans [SECURITY.md](SECURITY.md).

## Dépannage

**`coffre non initialisé : exécutez password-manager set-master`**
Aucun `vault.key` dans le répertoire de travail. Lancez `set-master`, ou placez-vous
dans le dossier qui contient votre coffre.

**`mot de passe maître incorrect`**
Le déballage de la clé a échoué. Il n'existe aucune procédure de récupération :
sans le mot de passe maître, le coffre est définitivement inaccessible.

**`fatal error: sqlite3.h: No such file or directory` à la compilation**
Les en-têtes SQLCipher manquent : `sudo apt-get install libsqlcipher-dev`.
Vérifiez aussi que `CGO_ENABLED=1` (valeur par défaut, sauf en compilation croisée).

**`bind: address already in use`**
Le port 8080 est déjà pris — souvent par l'autre commande du projet, `web` et
`api` utilisant le même port.

**Les templates ne se chargent pas au démarrage**
Les chemins sont relatifs au répertoire de travail : lancez le binaire depuis la
racine du dépôt, où se trouve `web/`.

**Les entrées ont disparu après un `docker run`**
Le conteneur a été recréé sans volume. Utilisez `docker compose up -d` ou
l'option `-v go-password-manager-data:/app`.

## Architecture du projet

```txt
go-password-manager/
├── cmd/                  Commandes CLI (cobra)
│   ├── root.go           Commande racine
│   ├── add.go            Ajouter un mot de passe
│   ├── list.go           Lister les mots de passe
│   ├── get.go            Récupérer un mot de passe
│   ├── delete.go         Supprimer une entrée
│   ├── setmaster.go      Initialiser le coffre / changer le mot de passe maître
│   ├── vault.go          Saisie du mot de passe maître et déverrouillage
│   ├── api.go            Serveur API local (endpoint JSON)
│   ├── web.go            Démarrage de l'interface web
│   └── tui.go            Menu interactif
├── internal/
│   ├── crypto/           AES-256-GCM, Argon2id, HKDF, génération de mots de passe
│   │   ├── kdf.go        Dérivation Argon2id, enveloppement de clé, sous-clés HKDF
│   │   ├── encryption.go Chiffrement authentifié des valeurs
│   │   └── password.go   Génération avec rejet d'échantillonnage
│   └── storage/          Coffre chiffré et fichier de clé
│       ├── vault.go      vault.key : sel + clé de données enveloppée
│       ├── database.go   Base SQLCipher, opérations CRUD
│       └── env.go        Génération et chargement du .env
├── web/                  Interface web (gorilla/mux + html/template + CSS maison)
│   ├── auth.go           Sessions, CSRF, rate-limiting, page de connexion
│   ├── server.go         Routes, handlers, en-têtes de sécurité, journal d'accès
│   ├── templates/        base.html + pages (accueil, coffre, ajout, générateur)
│   └── static/           app.css, app.js, theme.js, favicon, polices auto-hébergées
├── main.go               Point d'entrée du programme
├── Dockerfile            Image de build/exécution (multi-stage, non-root)
├── docker-compose.yml    Déploiement local avec volume persistant
├── .golangci.yml         Configuration du linter
├── SECURITY.md           Politique de signalement et limites du modèle de menace
└── .github/
    ├── workflows/        Intégration continue (build, lint, govulncheck, gitleaks)
    └── dependabot.yml    Mises à jour hebdomadaires des dépendances
```

## Statut du projet

Side-project personnel, développé pour pratiquer les fondamentaux Go
(structuration de modules, cryptographie de la bibliothèque standard, serveur
HTTP et middlewares, tests, CI/CD). Il est fonctionnel et testé, mais **n'a pas
été audité par un tiers** : ne lui confiez pas de secrets critiques sans en avoir
mesuré le risque.

Contribuer : forker, créer une branche, ouvrir une Pull Request. La CI doit
passer au vert.

## Licence

Ce projet est sous licence MIT (voir [LICENSE](LICENSE)).

Les polices embarquées dans `web/static/fonts/` sont distribuées sous
[SIL Open Font License 1.1](https://scripts.sil.org/OFL), indépendamment de la
licence du projet :

- **Inter** — © The Inter Project Authors
- **JetBrains Mono** — © The JetBrains Mono Project Authors
