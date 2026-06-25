# OpenCVE REST API

## Documentation

| Edition | Schema | Swagger UI |
|---------|--------|------------|
| **v1 legacy** (read-only) | `/api/schema/` | `/api/docs/` |
| **v2 primary** | `/api/v2/schema/` | `/api/v2/docs/` |

## v2 authentication

Organization Bearer token only:

```
Authorization: Bearer opc_org.<token_id>.<secret>
```

Tokens are created and revoked via the **web UI**, not via the API.

### Community tokens

- **Read-only** or **read-write** (`access_mode`) — the only user-facing permission level
- UI always stores `scopes=[]` (unrestricted according to `access_mode`, not zero permissions)
- Granular scopes are internal / Cloud future-proofing (`API_SCOPES_ENABLED=False` in Community)

## v1 legacy (`/api/`)

Read-only endpoints for backward compatibility. Supports HTTP Basic, session auth, or organization Bearer tokens.

Write operations are only available under `/api/v2/`.

## v2 highlights (`/api/v2/`)

- Global catalog: `GET /api/v2/cves`, weaknesses, vendors, activity, statistics
- Organization: `GET/PATCH /api/v2/organizations/{name}`, members, audit logs
- Projects: CRUD, subscriptions (`DELETE …/subscriptions?vendor=&product=`), CVE tracker, comments
- Notifications, automations, reports under project paths

Excluded from v2: token management API, tags, saved views, dashboards.
