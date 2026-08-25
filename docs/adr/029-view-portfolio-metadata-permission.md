| Status   | Date       | Author(s)                                        |
|:---------|:-----------|:--------------------------------------------------|
| Proposed | 2026-08-25 | [@thomas](https://github.com/Scalingo)            |

## Context

`VIEW_PORTFOLIO` is the only permission gating read access to the portfolio. It is required both by
endpoints that only reveal a project's *existence* and metadata (`GET /v1/project/lookup`,
`GET /v1/project/tag/{tag}`, `GET /v1/project`, etc.) and by endpoints that reveal a project's *content*
(`GET /v1/component/project/{uuid}`, `GET /v1/bom/cyclonedx/project/{uuid}`, dependency graph, metrics,
vulnerabilities, ...).

Automated integrations that only need to check whether a project already exists before uploading a new
SBOM (e.g. CI/scanner workers using `BOM_UPLOAD` + `PORTFOLIO_MANAGEMENT_CREATE`) are therefore forced to
also request `VIEW_PORTFOLIO`, which additionally grants them the ability to read every component list and
download every SBOM of every project they can see. There is no way to grant "can see the portfolio exists"
without also granting "can read the portfolio's content".

DT's own default "Automation" team (`VIEW_PORTFOLIO` + `BOM_UPLOAD`, seeded in `DatabaseSeedingInitTask`)
demonstrates that this coupling is a known, accepted trade-off today, not a deliberate design choice for
least-privilege automation accounts.

This is scoped narrowly to project-existence/metadata endpoints. It does not attempt the broader
role/permission overhaul discussed in [ADR-009](009-auth-and-roles.md); it introduces a single additive
permission consistent with the existing granular `PORTFOLIO_MANAGEMENT_*` pattern.

## Decision

Introduce a new permission, `VIEW_PORTFOLIO_METADATA`, that grants read access to project
existence/metadata only (name, version, tags, parent/children relationships) without granting access to
portfolio content (components, SBOMs, dependency graph, metrics, vulnerabilities).

- `VIEW_PORTFOLIO_METADATA` is additive: endpoints that reveal project existence/metadata now accept
  `VIEW_PORTFOLIO` **or** `VIEW_PORTFOLIO_METADATA` via `@PermissionRequired({...})`. Principals that
  already hold `VIEW_PORTFOLIO` are unaffected.
- The following `ProjectResource` (v1) endpoints accept the new permission: `GET /v1/project`,
  `/concise`, `/concise/{uuid}/children`, `/{uuid}`, `/latest/{name}`, `/lookup`, `/tag/{tag}`,
  `/classifier/{classifier}`, `/{uuid}/children`, `/{uuid}/children/classifier/{classifier}`,
  `/{uuid}/children/tag/{tag}`, `/withoutDescendantsOf/{uuid}`.
- All content-revealing endpoints (`ComponentResource`, `BomResource`, `DependencyGraphResource`,
  `MetricsResource`, `VulnerabilityResource`, `TagResource`, `ServiceResource`,
  `ComponentPropertyResource`, v2 `ComponentsResource`, v2 `ProjectsResource#listProjectComponents`)
  remain gated by `VIEW_PORTFOLIO` only and are unaffected by this change.
- No Flyway migration is required: permissions are seeded idempotently from the `Permissions` enum by
  `DatabaseSeedingInitTask.seedDefaultPermissions` at startup (`INSERT ... ON CONFLICT ("NAME") DO NOTHING`).
- The v4→v5 migrator's static `PermissionCatalog` seed list is updated to keep it in sync with the enum,
  per its own documented invariant.

## Consequences

- Automation-style API keys/teams (e.g. CI scanners uploading SBOMs) can be granted
  `VIEW_PORTFOLIO_METADATA` + `BOM_UPLOAD` + `PORTFOLIO_MANAGEMENT_CREATE` to check project existence and
  upload SBOMs, without being able to read any project's components or download any SBOM.
- Slight increase in permission surface/complexity: administrators must understand that
  `VIEW_PORTFOLIO_METADATA` is a strict subset of `VIEW_PORTFOLIO`, and that granting `VIEW_PORTFOLIO`
  implicitly supersedes it. The team UI (frontend, outside this repository) needs to surface the new
  permission and this relationship.
- Every new v1 project-listing endpoint added in the future must be deliberately classified as
  metadata-only or content-revealing when choosing its `@PermissionRequired` set; this is not enforced
  automatically and relies on code review.
- Does not address the broader permission/role redesign tracked in ADR-009; if that overhaul lands later,
  `VIEW_PORTFOLIO_METADATA` should be re-evaluated against the new model rather than duplicated.
