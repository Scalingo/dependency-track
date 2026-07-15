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

### Depuis une branche upstream (ex: `5.0.x`)

```bash
git fetch upstream
git checkout -b 5.0.x-scalingo upstream/5.0.x
git push -u origin 5.0.x-scalingo
```

### Depuis un tag upstream (ex: `v5.0.2`)

```bash
git fetch upstream --tags
git checkout -b 5.0.x-scalingo v5.0.2
git push -u origin 5.0.x-scalingo
```

> **Convention de nommage** : `{version-upstream-majeure.mineure}.x-scalingo`
> ex: `5.0.x-scalingo`, `5.1.x-scalingo`

---

## 3. Ajouter du code Scalingo

Travaillez sur des branches de feature dédiées pour faciliter les rebases futurs :

```bash
git checkout 5.0.x-scalingo
git checkout -b feat/my-scalingo-feature

# ... vos commits ...

git push origin feat/my-scalingo-feature
# Créer une PR vers 5.0.x-scalingo (pas vers master ni upstream)
```

Exemples de features déjà intégrées :
- `feat/secret-key-env-var` — chargement de la clé secrète depuis les variables d'env
- Support de la policy "Internal Status"

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
gh api --method POST \
  repos/Scalingo/dependency-track/actions/workflows/ci-release-scalingo.yaml/dispatches \
  -f ref=5.0.x-scalingo \
  -f inputs='{"scalingo-patch":"1"}'
```

### Ce que fait le workflow

```
prepare-release  →  calcule "5.0.3-scalingo.1" depuis pom.xml
create-release   →  bumpe tous les pom.xml, commit, crée le GitHub Release + tag
post-release     →  restaure "5.0.3-SNAPSHOT" sur la branche
```

> Le tag créé (`5.0.3-scalingo.1`) déclenche automatiquement **Publish CI**
> qui build les JARs et les attache à la release.

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

## 7. Publier les images Docker (optionnel)

Par défaut `publish-container: false` dans `ci-publish.yaml` — les images sont
buildées localement mais non pushées. Pour activer la publication :

1. Configurer les secrets dans **Settings → Secrets → Actions** :
   - `HUB_USERNAME` : identifiant Docker Hub
   - `HUB_ACCESSS_TOKEN` : token Docker Hub
2. Dans `.github/workflows/ci-publish.yaml`, passer `publish-container: true`

---

## 8. Fichiers clés du fork

| Fichier | Rôle |
|---|---|
| [.github/workflows/ci-release-scalingo.yaml](.github/workflows/ci-release-scalingo.yaml) | Workflow de release Scalingo |
| [.github/workflows/ci-publish.yaml](.github/workflows/ci-publish.yaml) | Build et attachment des artefacts (JAR, SBOM) |
| [.github/workflows/_meta-build.yaml](.github/workflows/_meta-build.yaml) | Build Maven + Docker réutilisable |

---

## Résumé des commandes courantes

```bash
# Nouvelle branche scalingo depuis upstream
git fetch upstream && git checkout -b 5.1.x-scalingo upstream/5.1.x

# Ajouter une feature
git checkout -b feat/my-feature 5.0.x-scalingo

# Synchro upstream
git fetch upstream && git rebase upstream/5.0.x && git push --force-with-lease

# Release (patch 1)
gh api --method POST \
  repos/Scalingo/dependency-track/actions/workflows/ci-release-scalingo.yaml/dispatches \
  -f ref=5.0.x-scalingo -f inputs='{"scalingo-patch":"1"}'

# Vérifier les runs
gh run list --repo Scalingo/dependency-track --branch 5.0.x-scalingo
```
