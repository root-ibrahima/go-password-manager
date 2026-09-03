# Politique de sécurité

## Versions supportées

Projet side-project à branche unique : seule la dernière version de `main` est
maintenue et reçoit des correctifs de sécurité.

## Signaler une vulnérabilité

Merci de **ne pas** ouvrir d'issue publique pour un problème de sécurité.
Utilisez l'onglet [Security > Report a vulnerability](../../security/advisories/new)
de ce dépôt (GitHub Security Advisories) pour un signalement privé.

## Modèle de cryptographie

- La clé de chiffrement des données est **aléatoire** et n'est jamais stockée en
  clair : elle est enveloppée (AES-256-GCM) par une clé dérivée du mot de passe
  maître via **Argon2id** (64 Mio, 3 passes, 4 voies), et conservée dans
  `vault.key` avec son sel.
- Le mot de passe maître n'est ni stocké ni haché : il est redemandé à chaque
  usage. Une saisie incorrecte fait échouer l'ouverture authentifiée de la clé
  enveloppée.
- Deux sous-clés distinctes sont dérivées par HKDF-SHA256 : l'une chiffre les
  valeurs, l'autre sert de passphrase SQLCipher. Aucune clé n'est réutilisée
  pour deux usages différents.
- Sur l'interface web, la clé de données ne vit qu'en mémoire, dans la session,
  et disparaît à la déconnexion ou à l'expiration (15 minutes d'inactivité).

## Limites connues du modèle de menace

- **Pas de TLS.** L'interface web sert du HTTP simple : elle est destinée à un
  usage local. Ne l'exposez pas sur Internet sans un reverse proxy TLS devant.
- **Pas de limitation de tentatives côté CLI.** Seule l'interface web limite les
  essais (5 échecs par minute et par IP). En local, le coût d'Argon2id reste le
  principal frein au bruteforce.
- **La mémoire du processus n'est pas verrouillée.** La clé de données et les
  mots de passe déchiffrés transitent en mémoire ; ils pourraient apparaître dans
  un fichier d'échange ou un vidage mémoire.
- **Le serveur API déchiffre à la demande.** Il exige le mot de passe maître à
  son démarrage et conserve la clé en mémoire tant qu'il tourne : toute personne
  disposant de l'`API_TOKEN` peut alors lire les mots de passe déchiffrés.
- **Perte du mot de passe maître = perte du coffre.** Il n'existe aucun mécanisme
  de récupération, par conception.
