# 🧺 Nos courses

Liste de courses partagée entre Thomas et Mickaël, utilisable sur téléphone.

**Adresse :** https://thomasduf0.github.io/Courses/

## Utilisation

- **Connexion** : choisir Thomas ou Mickaël, puis son mot de passe. L'appareil reste connecté ensuite.
- **🏠 Maison** : les produits sont rangés par catégorie. On coche ce qu'il faut acheter, on ajoute un produit en bas de chaque catégorie (avec une quantité si besoin). Un produit décoché reste dans le catalogue pour la prochaine fois. Le bouton **Modifier** d'une catégorie permet de renommer / supprimer des produits, et de renommer, déplacer ou supprimer la catégorie. La petite pastille T ou M indique qui a coché le produit.
- **🛒 Aux courses** : seuls les produits cochés apparaissent. On les touche quand ils sont dans le panier (ils passent en barré, en bas du rayon). **Terminer les courses** retire de la liste ce qui a été pris ; ce qui n'a pas été trouvé reste coché. L'écran reste allumé dans ce mode.
- Les modifications de l'un apparaissent chez l'autre en quelques secondes. Sans réseau, les changements sont gardés sur le téléphone et envoyés dès que la connexion revient.

Astuce : sur iPhone, *Partager → Sur l'écran d'accueil* pour l'avoir comme une appli.

## Fonctionnement technique

Site statique (HTML/CSS/JS, sans dépendance) servi par GitHub Pages. La liste est un fichier du dépôt, `data/liste.enc.json`, lu et écrit via l'API GitHub.

- Le jeton GitHub est stocké dans `config/acces.json`, **chiffré** (AES-GCM, clé dérivée du mot de passe par PBKDF2) une fois pour chaque personne. Aucun mot de passe n'est dans le code.
- La liste elle-même est chiffrée : le dépôt est public, mais son contenu reste illisible.
- Chaque modification est rejouée sur la dernière version du fichier, ce qui évite d'écraser les changements de l'autre.

### Jeton GitHub

Un jeton *fine-grained* limité à ce seul dépôt : GitHub → Settings → Developer settings → Personal access tokens → Fine-grained tokens → *Generate new token* ; Repository access : **Only select repositories → Courses** ; Permissions → Repository → **Contents : Read and write**.

Quand il expire : menu (pastille en haut à droite) → *Remplacer le jeton GitHub*.

Pour tout réinitialiser (nouveaux mots de passe, liste vide) : supprimer `config/acces.json` et `data/liste.enc.json` du dépôt, puis rouvrir le site.
