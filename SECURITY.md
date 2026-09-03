# Politique de sécurité

## Versions supportées

Projet side-project à branche unique : seule la dernière version de `main` est
maintenue et reçoit des correctifs de sécurité.

## Signaler une vulnérabilité

Merci de **ne pas** ouvrir d'issue publique pour un problème de sécurité.
Utilisez l'onglet [Security > Report a vulnerability](../../security/advisories/new)
de ce dépôt (GitHub Security Advisories) pour un signalement privé.

## Limites connues du modèle de menace

- `ENCRYPTION_KEY` (dans `.env`) n'est pas dérivée du mot de passe maître : elle
  protège les mots de passe stockés, mais toute personne ayant accès au fichier
  `.env` peut déchiffrer la base sans connaître le mot de passe maître. Une
  dérivation par KDF (Argon2id) à l'ouverture est une amélioration prévue.
- L'interface web sert du HTTP simple sans TLS (outil destiné à un usage local
  ou réseau interne) : ne pas l'exposer directement sur Internet sans un reverse
  proxy TLS devant.
- Aucune protection contre le bruteforce du mot de passe maître en CLI (seule
  l'interface web limite les tentatives, par IP, sur `/login`).
