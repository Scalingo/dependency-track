# Dependency-Track — Scalingo Fork

This document describes how to maintain and release a customized version of
Dependency-Track for Scalingo, starting from an upstream branch or tag.

## Overview

```
upstream/5.0.x  ──A──B──C──D──(next upstream release)
                              \
5.0.x-scalingo  ──A──B──C──D──── feat/scalingo-1 ── fix/scalingo-2
```

- **`upstream`**: remote pointing to `DependencyTrack/dependency-track`
- **`origin`**: remote pointing to `Scalingo/dependency-track` (the fork)
- **`5.0.x-scalingo`**: Scalingo working branch, based on `upstream/5.0.x`

Scalingo releases follow the scheme `{upstream-version}-scalingo.{N}`,
e.g. `5.0.3-scalingo.1`.

---

## 1. Prerequisites

- Git, Java 21 (Temurin), Maven 3.9+
- GitHub CLI (`gh`) authenticated on the Scalingo account
- Write access to `Scalingo/dependency-track`

Check configured remotes:

```bash
git remote -v
# origin    git@github.com:Scalingo/dependency-track.git
# upstream  ssh://git@github.com:22/DependencyTrack/dependency-track
```

If `upstream` is missing:

```bash
git remote add upstream ssh://git@github.com:22/DependencyTrack/dependency-track
```

---

## 2. Starting from a new upstream branch

> **Naming convention**: `{major.minor}.x-scalingo`
> e.g.: `5.0.x-scalingo`, `5.0.2.x-scalingo`, `5.1.x-scalingo`

### Case A — SNAPSHOT branch (e.g. `5.0.x`)

This is the simplest case: pom.xml is at `5.0.3-SNAPSHOT`, all versions are
consistent from the start.

```bash
git fetch upstream
git checkout -b 5.0.x-scalingo upstream/5.0.x
git push -u origin 5.0.x-scalingo
```

Add the release workflow:

```bash
git checkout master -- .github/workflows/ci-release-scalingo.yaml
git add .github/workflows/ci-release-scalingo.yaml
git commit -m "ci: add Scalingo release workflow"
git push origin 5.0.x-scalingo
```

### Case B — Frozen release branch (e.g. `5.0.2.x`)

These branches often have a **version inconsistency** between the root pom
(`5.0.2.1`) and sub-modules that reference the parent at `5.0.2`. Maven
refuses to parse the project in this state.

**Step 1**: create the scalingo branch

```bash
git fetch origin
git checkout -b 5.0.2.x-scalingo origin/5.0.2.x
```

**Step 2**: check version consistency

```bash
# Root pom version
git show HEAD:pom.xml | grep '<version>' | head -1
# E.g.: <version>5.0.2.1</version>

# Parent version referenced in a sub-module
git show HEAD:apiserver/pom.xml | grep -A3 '<parent>' | grep '<version>'
# E.g.: <version>5.0.2</version>   ← different → inconsistency!
```

**Step 3**: if inconsistent, align the root pom to the sub-modules version

```bash
# Edit pom.xml: change 5.0.2.1 → 5.0.2 in the project <version> tag
# (not in dependencies, only the root project <version>)
sed -i 's|<version>5\.0\.2\.1</version>|<version>5.0.2</version>|' pom.xml

git add pom.xml
git commit -m "fix: align root pom version with sub-modules (5.0.2)"
```

**Step 4**: add the workflow and push

```bash
git checkout master -- .github/workflows/ci-release-scalingo.yaml
git add .github/workflows/ci-release-scalingo.yaml
git commit -m "ci: add Scalingo release workflow"
git push -u origin 5.0.2.x-scalingo
```

**Step 5**: trigger the release by forcing the base version

```bash
# version-overwrite required here (no SNAPSHOT to parse)
gh api --method POST \
  repos/Scalingo/dependency-track/actions/workflows/ci-release-scalingo.yaml/dispatches \
  -f ref=5.0.2.x-scalingo \
  -f inputs='{"scalingo-patch":"1","version-overwrite":"5.0.2"}'
```

---

## 3. Adding Scalingo code

### Development workflow

Always work on a dedicated feature branch to ease future rebases:

```bash
git checkout 5.0.x-scalingo
git checkout -b feat/my-scalingo-feature

# ... your commits ...

git push origin feat/my-scalingo-feature
# Create a PR targeting 5.0.x-scalingo (not master or upstream)
```

### Where to place your code

| Need | Module | Example path |
|---|---|---|
| New analysis policy | `apiserver` | `apiserver/src/main/java/org/dependencytrack/policy/` |
| New vulnerability source | `apiserver` | `apiserver/src/main/java/org/dependencytrack/tasks/scanners/` |
| New REST v1 endpoint | `apiserver` | `apiserver/src/main/java/org/dependencytrack/resources/v1/` |
| New REST v2 endpoint | `api` | `api/src/main/openapi/` (spec-first) |
| New notification | `notification` | `notification/src/main/java/org/dependencytrack/notification/` |
| Configuration (env vars) | `apiserver` | `apiserver/src/main/resources/application.properties` |
| DB schema migration | `migration` | `migration/src/main/resources/org/dependencytrack/migration/` |

### Conventions to follow

- **Persistence**: use JDBI + raw SQL for all new code (not JDO/DataNucleus)
- **New endpoints**: add `@PermissionRequired` to every REST endpoint
- **Tests**: add one test per public method or endpoint added
- **Naming**: prefix your custom classes with `Scalingo` or place them in a `scalingo` sub-package to make them easy to find during rebases

### Examples of already integrated features

- `feat/secret-key-env-var` — loading the secret key from environment variables
- Support for the "Internal Status" policy (`InternalStatusPolicyEvaluator`)

---

## 4. Syncing with upstream

When a new upstream version is available, rebase your commits:

```bash
git fetch upstream

# Rebase the scalingo branch onto the latest upstream version
git checkout 5.0.x-scalingo
git rebase upstream/5.0.x

# Resolve any conflicts, then:
git rebase --continue

# Push (force required after rebase)
git push origin 5.0.x-scalingo --force-with-lease
```

> If conflicts are numerous, rebase feature by feature from your dedicated
> branches, then merge them onto `5.0.x-scalingo`.

---

## 5. Making a Scalingo release

The **Release CI (Scalingo)** GitHub Actions workflow handles everything automatically.

### Via the GitHub UI

1. Go to **Actions → Release CI (Scalingo)**
2. Click **Run workflow**
3. Select branch **`5.0.x-scalingo`**
4. Fill in the inputs:

| Input | Description | Example |
|---|---|---|
| `scalingo-patch` | Scalingo iteration number | `1`, `2`, `3`… |
| `version-overwrite` | Force the base version (optional) | `5.0.3` |

5. Click **Run workflow**

### Via GitHub CLI

```bash
# SNAPSHOT branch (version-overwrite optional)
gh api --method POST \
  repos/Scalingo/dependency-track/actions/workflows/ci-release-scalingo.yaml/dispatches \
  -f ref=5.0.x-scalingo \
  -f inputs='{"scalingo-patch":"1"}'

# Frozen release branch (version-overwrite REQUIRED)
gh api --method POST \
  repos/Scalingo/dependency-track/actions/workflows/ci-release-scalingo.yaml/dispatches \
  -f ref=5.0.2.x-scalingo \
  -f inputs='{"scalingo-patch":"1","version-overwrite":"5.0.2"}'
```

### What the workflow does

```
prepare-release  →  computes "5.0.3-scalingo.1" from pom.xml (or version-overwrite)
create-release   →  bumps all pom.xml files (git add -u), commits, creates the GitHub Release + tag
post-release     →  restores the SNAPSHOT version on the branch
```

> The created tag (`5.0.3-scalingo.1`) automatically triggers **Publish CI**
> which builds the JARs and attaches them to the release.

> **SNAPSHOT branch**: `post-release` restores `5.0.3-SNAPSHOT`  
> **Frozen branch**: `post-release` restores `5.0.2-SNAPSHOT` (the branch evolves to SNAPSHOT)

### Incrementing the Scalingo patch

Same upstream base, new Scalingo fix:

```bash
# Trigger with scalingo-patch=2 → produces 5.0.3-scalingo.2
gh api --method POST \
  repos/Scalingo/dependency-track/actions/workflows/ci-release-scalingo.yaml/dispatches \
  -f ref=5.0.x-scalingo \
  -f inputs='{"scalingo-patch":"2"}'
```

---

## 6. Triggering Publish CI manually

If Publish CI did not trigger automatically on the release:

```bash
gh api --method POST \
  repos/Scalingo/dependency-track/actions/workflows/ci-publish.yaml/dispatches \
  -d '{"ref":"5.0.3-scalingo.1"}'
```

---

## 7. Publishing Docker images (optional)

By default `publish-container: false` in `ci-publish.yaml` — images are
built locally but not pushed. To enable publishing:

1. Configure secrets in **Settings → Secrets → Actions**:
   - `HUB_USERNAME`: Docker Hub username
   - `HUB_ACCESSS_TOKEN`: Docker Hub token
2. In `.github/workflows/ci-publish.yaml`, set `publish-container: true`

---

## 8. Key fork files

| File | Role |
|---|---|
| [.github/workflows/ci-release-scalingo.yaml](.github/workflows/ci-release-scalingo.yaml) | Scalingo release workflow |
| [.github/workflows/ci-publish.yaml](.github/workflows/ci-publish.yaml) | Build and artifact attachment (JAR, SBOM) |
| [.github/workflows/_meta-build.yaml](.github/workflows/_meta-build.yaml) | Reusable Maven + Docker build |

---

## Common commands cheatsheet

```bash
# --- New branch from an upstream SNAPSHOT branch ---
git fetch upstream && git checkout -b 5.1.x-scalingo upstream/5.1.x
git checkout master -- .github/workflows/ci-release-scalingo.yaml
git add .github/workflows/ci-release-scalingo.yaml && git commit -m "ci: add Scalingo release workflow"
git push -u origin 5.1.x-scalingo

# --- New branch from a frozen release branch ---
git fetch origin && git checkout -b 5.0.2.x-scalingo origin/5.0.2.x
# Check root pom vs sub-modules consistency, then if needed:
# sed -i 's|<version>5\.0\.2\.1</version>|<version>5.0.2</version>|' pom.xml
git checkout master -- .github/workflows/ci-release-scalingo.yaml
git add . && git commit -m "ci: add Scalingo release workflow"
git push -u origin 5.0.2.x-scalingo

# --- Add a feature ---
git checkout -b feat/my-feature 5.0.x-scalingo
# ... commits ...
git push origin feat/my-feature
# PR targeting 5.0.x-scalingo

# --- Sync upstream ---
git fetch upstream && git rebase upstream/5.0.x && git push --force-with-lease

# --- Release from SNAPSHOT branch ---
gh api --method POST \
  repos/Scalingo/dependency-track/actions/workflows/ci-release-scalingo.yaml/dispatches \
  -f ref=5.0.x-scalingo -f inputs='{"scalingo-patch":"1"}'

# --- Release from frozen branch (version-overwrite required) ---
gh api --method POST \
  repos/Scalingo/dependency-track/actions/workflows/ci-release-scalingo.yaml/dispatches \
  -f ref=5.0.2.x-scalingo -f inputs='{"scalingo-patch":"1","version-overwrite":"5.0.2"}'

# --- Manual Publish CI (if not triggered automatically) ---
gh api --method POST \
  repos/Scalingo/dependency-track/actions/workflows/ci-publish.yaml/dispatches \
  -d '{"ref":"5.0.3-scalingo.1"}'

# --- Check runs ---
gh run list --repo Scalingo/dependency-track --branch 5.0.x-scalingo
```
