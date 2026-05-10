# Scanner de vulnérabilité web

Application web pour scanner un site web créé avec Vibe et détecter des points de sécurité avancés.

## Installation

1. `npm install`
2. `npm run dev`

## Utilisation

- Saisissez l'URL du site web à vérifier.
- Cliquez sur `Lancer le scan`.
- Consultez les sections : statut HTTP, score, issues, en-têtes de sécurité, TLS et détection Vibe.
- Exportez le rapport au format JSON ou CSV.

## Fonctionnalités

- Interface React + Vite moderne
- Backend Express pour récupérer le site et analyser le contenu
- Analyse des en-têtes de sécurité clés : HSTS, CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy, Cache-Control
- Vérification TLS/SSL du certificat : validité, autorisation, période de validité
- Détection Vibe via marqueurs HTML et en-têtes
- Export JSON/CSV du rapport de scan

## Scripts

- `npm run dev` : lance Vite et le serveur de scan
- `npm run build` : compile le frontend
- `npm run preview` : prévisualise le build
- `npm start` : démarre le serveur de scan seul
