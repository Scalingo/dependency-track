# Dependency-Track — Fork Scalingo

Ce document décrit comment maintenir et releaser une version customisée de
Dependency-Track pour Scalingo, en partant d'une branche ou d'un tag upstream.

## Vue d'ensemble

```
upstream/5.0.x  ──A──B──C──D──(next upstream release)
                              \
5.0.x-scalingo  ──A──B──C──D──── feat/scalingo-1 ── fix/scalingo-2
```

- **`upstream`** : remote pointant sur `DependencyTrack/dependency-track`
- **`origin`** : remote pointant sur `Scalingo/dependency-track` (le fork)
- **`5.0.x-scalingo`** : branche de travail Scalingo, basée sur `upstream/5.0.x`

Les releases Scalingo suivent le schéma `{version-upstream}-scalingo.{N}`,
par exemple `5.0.3-scalingo.1`.

---

## 1. Prérequis

- Git, Java 21 (Temurin), Maven 3.9+
- GitHub CLI (`gh`) authentifié sur le compte Scalingo
- Accès en écriture sur `Scalingo/dependency-track`

Vérifier les remotes configurés :

```bash
git remote -v
# origin    git@github.com:Scalingo/dependency-track.git
# upstream  ssh://git@github.com:22/DependencyTrack/dependency-track
```

Si `upstream` est absent :

```bash
git remote add upstream ssh://git@github.com:22/DependencyTrack/dependency-track
```

---

## 2. Partir d'une nouvelle branche upstream

> **Convention de nommage** : `{majeure.mineure}.x-scalingo`
> ex: `5.0.x-scalingo`, `5.0.2.x-scalingo`, `5.1.x-scalingo`

### Cas A — Branche SNAPSHOT (ex: `5.0.x`)

C'est le cas le plus simple : le pom.xml est à `5.0.3-SNAPSHOT`, toutes les
versions sont cohérentes d'emblée.

```bash
git fetch upstream
git checkout -b 5.0.x-scalingo upstream/5.0.x
git push -u origin 5.0.x-scalingo
```

Ajoutez le workflow de release :

```bash
git checkout master -- .github/workflows/ci-release-scalingo.yaml
git add .github/workflows/ci-release-scalingo.yaml
git commit -m "ci: add Scalingo release workflow"
git push origin 5.0.x-scalingo
```

### Cas B — Branche de release figée (ex: `5.0.2.x`)

Ces branches ont souvent une **incohérence de version** entre le root pom
(`5.0.2.1`) et les sous-modules qui référencent le parent à `5.0.2`. Maven
refuse de parser le projet dans cet état.

**Étape 1** : créer la branche scalingo

```bash
git fetch origin
git checkout -b 5.0.2.x-scalingo origin/5.0.2.x
```

**Étape 2** : vérifier la cohérence des versions

```bash
# Version du root pom
git show HEAD:pom.xml | grep '<version>' | head -1
# Ex: <version>5.0.2.1</version>

# Version du parent référencée dans un sous-module
git show HEAD:apiserver/pom.xml | grep -A3 '<parent>' | grep '<version>'
# Ex: <version>5.0.2</version>   ← différent → incohérence !
```

**Étape 3** : si incohérence, aligner le root pom sur la version des sous-modules

```bash
# Éditer pom.xml : changer 5.0.2.1 → 5.0.2 dans la balise <version> du projet
# (pas dans les dépendances, uniquement le <version> du projet racine)
sed -i 's|<version>5\.0\.2\.1</version>|<version>5.0.2</version>|' pom.xml

git add pom.xml
git commit -m "fix: align root pom version with sub-modules (5.0.2)"
```

**Étape 4** : ajouter le workflow et pousser

```bash
git checkout master -- .github/workflows/ci-release-scalingo.yaml
git add .github/workflows/ci-release-scalingo.yaml
git commit -m "ci: add Scalingo release workflow"
git push -u origin 5.0.2.x-scalingo
```

**Étape 5** : déclencher la release en forçant la version de base

```bash
# version-overwrite obligatoire ici (pas de SNAPSHOT à parser)
gh api --method POST \
  repos/Scalingo/dependency-track/actions/workflows/ci-release-scalingo.yaml/dispatches \
  -f ref=5.0.2.x-scalingo \
  -f inputs='{"scalingo-patch":"1","version-overwrite":"5.0.2"}'
```

---

## 3. Ajouter du code Scalingo

### Workflow de développement

Travaillez toujours sur une branche de feature dédiée pour faciliter les rebases futurs :

```bash
git checkout 5.0.x-scalingo
git checkout -b feat/my-scalingo-feature

# ... vos commits ...

git push origin feat/my-scalingo-feature
# Créer une PR vers 5.0.x-scalingo (pas vers master ni upstream)
```

### Où placer votre code

| Besoin | Module | Exemple de chemin |
|---|---|---|
| Nouvelle policy d'analyse | `apiserver` | `apiserver/src/main/java/org/dependencytrack/policy/` |
| Nouvelle source de vulnérabilités | `apiserver` | `apiserver/src/main/java/org/dependencytrack/tasks/scanners/` |
| Nouveau endpoint REST v1 | `apiserver` | `apiserver/src/main/java/org/dependencytrack/resources/v1/` |
| Nouveau endpoint REST v2 | `api` | `api/src/main/openapi/` (spec-first) |
| Nouvelle notification | `notification` | `notification/src/main/java/org/dependencytrack/notification/` |
| Configuration (variables d'env) | `apiserver` | `apiserver/src/main/resources/application.properties` |
| Migration de schéma BDD | `migration` | `migration/src/main/resources/org/dependencytrack/migration/` |

### Conventions à respecter

- **Persistance** : utilisez JDBI + SQL brut pour tout nouveau code (pas JDO/DataNucleus)
- **Nouveaux endpoints** : ajoutez `@PermissionRequired` pour tout endpoint REST
- **Tests** : ajoutez un test par méthode publique ou endpoint ajouté
- **Nommage** : préfixez vos classes custom avec `Scalingo` ou placez-les dans un sous-package `scalingo` pour les retrouver facilement lors des rebases

### Exemples de features déjà intégrées

- `feat/secret-key-env-var` — chargement de la clé secrète depuis les variables d'env
- Support de la policy "Internal Status" (`InternalStatusPolicyEvaluator`)

---

## 4. Synchroniser avec l'upstream

Quand une nouvelle version upstream est disponible, rebasez vos commits :

```bash
git fetch upstream

# Rebaser la branche scalingo sur la dernière version upstream
git checkout 5.0.x-scalingo
git rebase upstream/5.0.x

# Résoudre les conflits éventuels, puis :
git rebase --continue

# Pousser (force nécessaire après rebase)
git push origin 5.0.x-scalingo --force-with-lease
```

> Si les conflits sont nombreux, rebasez feature par feature depuis vos branches
> dédiées, puis mergez-les sur `5.0.x-scalingo`.

---

## 5. Faire une release Scalingo

Le workflow GitHub Actions **Release CI (Scalingo)** gère tout automatiquement.

### Via l'interface GitHub

1. Aller sur **Actions → Release CI (Scalingo)**
2. Cliquer **Run workflow**
3. Sélectionner la branche **`5.0.x-scalingo`**
4. Renseigner les inputs :

| Input | Description | Exemple |
|---|---|---|
| `scalingo-patch` | Numéro d'itération Scalingo | `1`, `2`, `3`… |
| `version-overwrite` | Forcer la version de base (optionnel) | `5.0.3` |

5. Cliquer **Run workflow**

### Via GitHub CLI

```bash
# Branche SNAPSHOT (version-overwrite optionnel)
gh api --method POST \
  repos/Scalingo/dependency-track/actions/workflows/ci-release-scalingo.yaml/dispatches \
  -f ref=5.0.x-scalingo \
  -f inputs='{"scalingo-patch":"1"}'

# Branche de release figée (version-overwrite OBLIGATOIRE)
gh api --method POST \
  repos/Scalingo/dependency-track/actions/workflows/ci-release-scalingo.yaml/dispatches \
  -f ref=5.0.2.x-scalingo \
  -f inputs='{"scalingo-patch":"1","version-overwrite":"5.0.2"}'
```

### Ce que fait le workflow

```
prepare-release  →  calcule "5.0.3-scalingo.1" depuis pom.xml (ou version-overwrite)
create-release   →  bumpe tous les pom.xml (git add -u), commit, crée le GitHub Release + tag
post-release     →  restaure la version SNAPSHOT sur la branche
```

> Le tag créé (`5.0.3-scalingo.1`) déclenche automatiquement **Publish CI**
> qui build les JARs et les attache à la release.

> **Branche SNAPSHOT** : `post-release` restaure `5.0.3-SNAPSHOT`  
> **Branche figée** : `post-release` restaure `5.0.2-SNAPSHOT` (la branche évolue vers SNAPSHOT)

### Incrémenter le patch Scalingo

Même base upstream, nouvelle correction Scalingo :

```bash
# Déclencher avec scalingo-patch=2 → produit 5.0.3-scalingo.2
gh api --method POST \
  repos/Scalingo/dependency-track/actions/workflows/ci-release-scalingo.yaml/dispatches \
  -f ref=5.0.x-scalingo \
  -f inputs='{"scalingo-patch":"2"}'
```

---

## 6. Déclencher Publish CI manuellement

Si Publish CI ne s'est pas déclenché automatiquement sur la release :

```bash
gh api --method POST \
  repos/Scalingo/dependency-track/actions/workflows/ci-publish.yaml/dispatches \
  -d '{"ref":"5.0.3-scalingo.1"}'
```

---

## 7. Publier les images Docker sur Docker Hub

`ci-publish.yaml` build et pousse déjà les images `apiserver` et `v4-migrator`
vers `ghcr.io/scalingo/*` à chaque tag de release (`publish-container: true`).

L'image `apiserver` est en plus miroitée vers Docker Hub
(`docker.io/scalingo/dependency-track`, tags `<version>` et `latest`) par le
workflow dédié
[`.github/workflows/mirror-container-image-scalingo.yml`](.github/workflows/mirror-container-image-scalingo.yml),
déclenché sur l'événement `registry_package: published` une fois l'image
poussée sur ghcr.io.

Prérequis : configurer les secrets suivants dans **Settings → Secrets →
Actions** du repo `Scalingo/dependency-track` :
- `DOCKER_HUB_USERNAME` : identifiant Docker Hub
- `DOCKER_HUB_TOKEN` : access token Docker Hub (scope Read & Write)

Ce workflow est propre au fork Scalingo (jamais présent côté upstream), donc
sans risque de conflit lors des rebases.

---

## 8. Fichiers clés du fork

| Fichier | Rôle |
|---|---|
| [.github/workflows/ci-release-scalingo.yaml](.github/workflows/ci-release-scalingo.yaml) | Workflow de release Scalingo |
| [.github/workflows/ci-publish.yaml](.github/workflows/ci-publish.yaml) | Build et attachment des artefacts (JAR, SBOM) |
| [.github/workflows/_meta-build.yaml](.github/workflows/_meta-build.yaml) | Build Maven + Docker réutilisable |
| [.github/workflows/mirror-container-image-scalingo.yml](.github/workflows/mirror-container-image-scalingo.yml) | Miroir de l'image apiserver vers Docker Hub |

---

## Résumé des commandes courantes

```bash
# --- Nouvelle branche depuis une branche SNAPSHOT upstream ---
git fetch upstream && git checkout -b 5.1.x-scalingo upstream/5.1.x
git checkout master -- .github/workflows/ci-release-scalingo.yaml
git add .github/workflows/ci-release-scalingo.yaml && git commit -m "ci: add Scalingo release workflow"
git push -u origin 5.1.x-scalingo

# --- Nouvelle branche depuis une branche de release figée ---
git fetch origin && git checkout -b 5.0.2.x-scalingo origin/5.0.2.x
# Vérifier cohérence root pom vs sous-modules, puis si besoin :
# sed -i 's|<version>5\.0\.2\.1</version>|<version>5.0.2</version>|' pom.xml
git checkout master -- .github/workflows/ci-release-scalingo.yaml
git add . && git commit -m "ci: add Scalingo release workflow"
git push -u origin 5.0.2.x-scalingo

# --- Ajouter une feature ---
git checkout -b feat/my-feature 5.0.x-scalingo
# ... commits ...
git push origin feat/my-feature
# PR vers 5.0.x-scalingo

# --- Synchro upstream ---
git fetch upstream && git rebase upstream/5.0.x && git push --force-with-lease

# --- Release depuis branche SNAPSHOT ---
gh api --method POST \
  repos/Scalingo/dependency-track/actions/workflows/ci-release-scalingo.yaml/dispatches \
  -f ref=5.0.x-scalingo -f inputs='{"scalingo-patch":"1"}'

# --- Release depuis branche figée (version-overwrite obligatoire) ---
gh api --method POST \
  repos/Scalingo/dependency-track/actions/workflows/ci-release-scalingo.yaml/dispatches \
  -f ref=5.0.2.x-scalingo -f inputs='{"scalingo-patch":"1","version-overwrite":"5.0.2"}'

# --- Publish CI manuel (si non déclenché automatiquement) ---
gh api --method POST \
  repos/Scalingo/dependency-track/actions/workflows/ci-publish.yaml/dispatches \
  -d '{"ref":"5.0.3-scalingo.1"}'

# --- Vérifier les runs ---
gh run list --repo Scalingo/dependency-track --branch 5.0.x-scalingo
```
