# open-filerep

A lightweight REST API for tracking file reputation by SHA-256, backed by [Badger](https://github.com/dgraph-io/badger) — an embedded key-value store written in Go.
No external database server required. Designed as a companion service for ClamAV mail-scanning pipelines (e.g. via a Milter interface) where you need fast, persistent lookups of already-scanned files, with correct antivirus-specific update semantics and multi-source reputation tracking.


## Data model

Each record is identified by the SHA-256 of the file content.

| Field        | Type   | Description                                                        |
|--------------|--------|--------------------------------------------------------------------|
| `sha256`     | string | 64-character lowercase hex — primary key                           |
| `fileNames`  | array  | All known file names for this hash (deduped, grows on each report) |
| `status`     | string | `clean` · `infected` · `quarantined` · `error` · `unknown`         |
| `action`     | string | `allow` · `block` · `quarantine` · `whitelist` · `monitor`  — `whitelist` is a persistent admin trust override that beats scanner results |
| `threat`     | string | Virus or threat name as reported by the scanner (optional)         |
| `source`     | string | `clamav` · `virustotal` · `admin` · `threat-feed` · `manual`       |
| `pattern`    | string | Scanner pattern / database version (optional)                      |
| `firstSeen`  | int64  | Unix epoch seconds — when this hash was first submitted            |
| `lastSeen`   | int64  | Unix epoch seconds — when the record was last updated              |
| `note`       | string | Free-text remark (optional)                                        |

`firstSeen` is set on first write and never overwritten. `lastSeen` is updated on every write. Both are stored as Unix epoch `int64`; the text and header APIs render them as RFC-3339 for readability.

All write operations accept a single `"fileName"` string. The record accumulates all distinct names ever reported for that hash into the `fileNames` array — the same content circulates under many names, especially for malware.

Two hashes are used throughout this document:

| Label | SHA-256 |
|-------|---------|
| `SHA_CLEAN` | `a3f1c2d4e5b6789012345678901234567890123456789012345678901234abcd` |
| `SHA_INFECTED` | `131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267` |


## API

Base path: `http://localhost:8080`

The API has two layers:

- **`/files/*`** — generic CRUD, no business rules, full control
- **`/scan/*`** — antivirus-specific endpoints that enforce update rules


## Generic CRUD — `/files`

### Add / upsert a record

```
POST /files
Content-Type: application/json
```

If `action` is omitted it is derived from `status` (`clean` → `allow`, `infected`/`quarantined` → `block`, otherwise `monitor`). SHA-256 is normalised to lowercase. `firstSeen` and `lastSeen` are always set by the server.

```bash
curl -s -X POST http://localhost:8080/files \
  -H 'Content-Type: application/json' \
  -d '{
    "sha256":   "a3f1c2d4e5b6789012345678901234567890123456789012345678901234abcd",
    "fileName": "invoice.pdf",
    "status":   "clean",
    "action":   "allow",
    "source":   "clamav",
    "pattern":  "daily.cvd:26843",
    "note":     "no threats found"
  }' | jq .
```

**Response `201 Created`:**

```json
{
  "sha256": "a3f1c2d4e5b6789012345678901234567890123456789012345678901234abcd",
  "fileNames": ["invoice.pdf"],
  "effectiveStatus": "clean",
  "effectiveAction": "allow",
  "resolvedBy": "clamav",
  "sources": [
    {
      "source":     "clamav",
      "status":     "clean",
      "action":     "allow",
      "pattern":    "daily.cvd:26843",
      "note":       "no threats found",
      "reportedAt": 1743000000
    }
  ],
  "firstSeen": 1743000000,
  "lastSeen":  1743000000
}
```


### Get a record

```
GET /files/{sha256}
```

```bash
curl -s http://localhost:8080/files/a3f1c2d4e5b6789012345678901234567890123456789012345678901234abcd \
  | jq .
```

**Response `200 OK`:**

```json
{
  "sha256": "a3f1c2d4e5b6789012345678901234567890123456789012345678901234abcd",
  "fileNames": ["invoice.pdf"],
  "effectiveStatus": "clean",
  "effectiveAction": "allow",
  "resolvedBy": "clamav",
  "sources": [
    {
      "source":     "clamav",
      "status":     "clean",
      "action":     "allow",
      "pattern":    "daily.cvd:26843",
      "note":       "no threats found",
      "reportedAt": 1743000000
    }
  ],
  "firstSeen": 1743000000,
  "lastSeen":  1743000000
}
```

Returns `404` if the hash is not found.


### Update a record

```
PUT /files/{sha256}
Content-Type: application/json
```

Only fields present in the body are applied; omitted fields keep their existing value.
No business rules are enforced — use `/scan/*` if you want antivirus semantics.
`lastSeen` is always updated. `firstSeen` is never changed by a PUT.

```bash
curl -s -X PUT \
  http://localhost:8080/files/a3f1c2d4e5b6789012345678901234567890123456789012345678901234abcd \
  -H 'Content-Type: application/json' \
  -d '{"status": "quarantined", "action": "block", "note": "moved to /var/quarantine"}' \
  | jq .
```

**Response `200 OK`:**

```json
{
  "sha256": "a3f1c2d4e5b6789012345678901234567890123456789012345678901234abcd",
  "fileNames": ["invoice.pdf"],
  "effectiveStatus": "quarantined",
  "effectiveAction": "block",
  "resolvedBy": "clamav",
  "sources": [
    {
      "source":     "clamav",
      "status":     "quarantined",
      "action":     "block",
      "pattern":    "daily.cvd:26843",
      "note":       "moved to /var/quarantine",
      "reportedAt": 1743003600
    }
  ],
  "firstSeen": 1743000000,
  "lastSeen":  1743003600
}
```


### Delete a record

```
DELETE /files/{sha256}
```

```bash
curl -s -X DELETE \
  http://localhost:8080/files/a3f1c2d4e5b6789012345678901234567890123456789012345678901234abcd \
  -o /dev/null -w "%{http_code}\n"
```

**Response `204 No Content`**, or `404` if not found.


### List records

```
GET /files
GET /files?status=clean
GET /files?status=infected
GET /files?status=quarantined
```

Returns a JSON array. Always returns `[]` when nothing matches, never `null`.

```bash
# all records
curl -s http://localhost:8080/files | jq .

# only infected
curl -s http://localhost:8080/files?status=infected | jq .
```

**Response `200 OK`:**

```json
[
  {
    "sha256": "131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267",
    "fileNames": ["eicar.com", "eicar.txt"],
    "effectiveStatus": "infected",
    "effectiveAction": "block",
    "resolvedBy": "clamav",
    "sources": [
      {
        "source":     "clamav",
        "status":     "infected",
        "action":     "block",
        "threat": "Eicar-Signature",
        "pattern":    "daily.cvd:26843",
        "note":       "ClamAV 1.4",
        "reportedAt": 1743001200
      }
    ],
    "firstSeen": 1743001200,
    "lastSeen":  1743001200
  }
]
```


## Scan API — `/scan`

These endpoints enforce the antivirus business rules in priority order:

> 1. **Whitelist beats everything.** If any source carries `action: whitelist`, the effective action is always `allow` — scanner results cannot override an explicit admin trust decision.
> 2. **Infected beats clean.** An infected result always overwrites a clean one. A clean result does not overwrite an infected one.
> 3. **Clean only updates if safe to do so.** A clean report is stored only when the file was not already marked infected or quarantined.


### Check before scanning

```
GET /scan/{sha256}?pattern={version}
```

Call this before starting a scan to decide whether scanning is necessary.

| `action`  | Meaning                                                        |
|-----------|----------------------------------------------------------------|
| `scan`    | File not seen before — go ahead and scan                       |
| `skip`    | Already infected/quarantined, or same pattern already stored   |
| `rescan`  | Stored result is clean but with an older pattern — rescan      |

```bash
curl -s "http://localhost:8080/scan/a3f1c2d4e5b6789012345678901234567890123456789012345678901234abcd?pattern=daily.cvd:26843" \
  | jq .
```

**Response `200 OK` — file not seen before (`scan`):**

```json
{
  "action": "scan",
  "reason": "no record found",
  "record": null
}
```

**Response `200 OK` — clean result but pattern outdated (`rescan`):**

```json
{
  "action": "rescan",
  "reason": "pattern outdated (stored: daily.cvd:26800, current: daily.cvd:26843)",
  "record": {
    "sha256": "a3f1c2d4e5b6789012345678901234567890123456789012345678901234abcd",
    "fileNames": ["invoice.pdf"],
    "effectiveStatus": "clean",
    "effectiveAction": "allow",
    "resolvedBy": "clamav",
    "sources": [ { "source": "clamav", "status": "clean", "pattern": "daily.cvd:26800", "reportedAt": 1743000000 } ],
    "firstSeen": 1743000000,
    "lastSeen":  1743000000
  }
}
```

**Response `200 OK` — already infected (`skip`):**

```json
{
  "action": "skip",
  "reason": "file is already infected — no rescan needed",
  "record": {
    "sha256": "131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267",
    "fileNames": ["eicar.com"],
    "effectiveStatus": "infected",
    "effectiveAction": "block",
    "resolvedBy": "clamav",
    "sources": [ { "source": "clamav", "status": "infected", "threat": "Eicar-Signature", "pattern": "daily.cvd:26843", "reportedAt": 1743001200 } ],
    "firstSeen": 1743001200,
    "lastSeen":  1743001200
  }
}
```


### Report a clean result

```
POST /scan/clean
Content-Type: application/json
```

**Rules applied:**
- If the stored status is `infected` or `quarantined` → record is **not** updated (`stored: false`)
- Otherwise → record is created or updated with the new pattern and timestamp

```bash
curl -s -X POST http://localhost:8080/scan/clean \
  -H 'Content-Type: application/json' \
  -d '{
    "sha256":   "a3f1c2d4e5b6789012345678901234567890123456789012345678901234abcd",
    "fileName": "invoice.pdf",
    "pattern":  "daily.cvd:26843",
    "source":   "clamav",
    "note":     "no threats found"
  }' | jq .
```

**Response `200 OK` — stored:**

```json
{
  "stored": true,
  "reason": "clean result recorded",
  "record": {
    "sha256": "a3f1c2d4e5b6789012345678901234567890123456789012345678901234abcd",
    "fileNames": ["invoice.pdf"],
    "effectiveStatus": "clean",
    "effectiveAction": "allow",
    "resolvedBy": "clamav",
    "sources": [
      {
        "source":     "clamav",
        "status":     "clean",
        "action":     "allow",
        "pattern":    "daily.cvd:26843",
        "note":       "no threats found",
        "reportedAt": 1743000000
      }
    ],
    "firstSeen": 1743000000,
    "lastSeen":  1743000000
  }
}
```

**Response `200 OK` — rejected (existing infected result preserved):**

```json
{
  "stored": false,
  "reason": "existing infected result preserved — infected beats clean",
  "record": { "..." : "..." }
}
```


### Report an infected result

```
POST /scan/infected
Content-Type: application/json
```

`action` is automatically set to `block`. Infected always wins — always stored regardless of previous status.

```bash
curl -s -X POST http://localhost:8080/scan/infected \
  -H 'Content-Type: application/json' \
  -d '{
    "sha256":     "131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267",
    "fileName":   "eicar.com",
    "pattern":    "daily.cvd:26843",
    "threat": "Eicar-Signature",
    "source":     "clamav",
    "note":       "ClamAV 1.4"
  }' | jq .
```

**Response `200 OK`:**

```json
{
  "stored": true,
  "reason": "infected result recorded",
  "record": {
    "sha256": "131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267",
    "fileNames": ["eicar.com"],
    "effectiveStatus": "infected",
    "effectiveAction": "block",
    "resolvedBy": "clamav",
    "sources": [
      {
        "source":     "clamav",
        "status":     "infected",
        "action":     "block",
        "threat": "Eicar-Signature",
        "pattern":    "daily.cvd:26843",
        "note":       "ClamAV 1.4",
        "reportedAt": 1743001200
      }
    ],
    "firstSeen": 1743001200,
    "lastSeen":  1743001200
  }
}
```


## Admin whitelist

A whitelist entry is an explicit admin trust decision that persists across rescans. Once a file is whitelisted, scanner reports (`/scan/clean`, `/scan/infected`, `/simple/*`) can still add their source entries to the record, but the effective action remains `allow` — the admin intent wins.

### Resolution priority

```
1. whitelist  (source: admin, action: whitelist)  →  effective action: allow — beats everything
2. infected   (from any scanner source)            →  effective action: block — beats clean
3. clean      (from any scanner source)            →  effective action: allow — only if not infected
```

### Adding a whitelist entry

Use `POST /files` with `source: admin` and `action: whitelist`. No scan endpoint is needed — this is a direct CRUD write that bypasses scanner business rules.

```bash
curl -s -X POST http://localhost:8080/files \
  -H 'Content-Type: application/json' \
  -d '{
    "sha256":   "a3f1c2d4e5b6789012345678901234567890123456789012345678901234abcd",
    "fileName": "internal-deploy-tool.exe",
    "status":   "clean",
    "action":   "whitelist",
    "source":   "admin",
    "note":     "internal build — approved by ops 2026-03-26"
  }' | jq .
```

**Response `201 Created`:**

```json
{
  "sha256": "a3f1c2d4e5b6789012345678901234567890123456789012345678901234abcd",
  "fileNames": ["internal-deploy-tool.exe"],
  "effectiveStatus": "clean",
  "effectiveAction": "whitelist",
  "resolvedBy": "admin",
  "sources": [
    {
      "source":     "admin",
      "status":     "clean",
      "action":     "whitelist",
      "note":       "internal build — approved by ops 2026-03-26",
      "reportedAt": 1743012000
    }
  ],
  "firstSeen": 1743012000,
  "lastSeen":  1743012000
}
```

Even if ClamAV subsequently reports this hash as infected, `effectiveAction` stays `whitelist` and the mail pipeline lets it through.

### Verifying the whitelist entry holds

```bash
# Simulate ClamAV reporting it infected — whitelist must win
curl -s -X POST http://localhost:8080/scan/infected \
  -H 'Content-Type: application/json' \
  -d '{
    "sha256":   "a3f1c2d4e5b6789012345678901234567890123456789012345678901234abcd",
    "threat":   "Heuristic.Suspicious",
    "pattern":  "daily.cvd:26900",
    "source":   "clamav"
  }' | jq '.record.effectiveAction'
```

Expected result: `"whitelist"` — ClamAV's infected report is stored in `sources` but does not change the effective outcome.

### Removing a whitelist entry

Delete the entire record. The next scan will start fresh and ClamAV's result will determine the new effective status.

```bash
curl -s -X DELETE \
  http://localhost:8080/files/a3f1c2d4e5b6789012345678901234567890123456789012345678901234abcd \
  -o /dev/null -w "%{http_code}\n"
```

After deletion, `GET /scan/{sha256}` returns `action: scan` — the file is unknown again.


## Simple query-string API — `/simple`

All parameters are query-string arguments. All responses are `text/plain` with `key=value` lines — no JSON body required on either side. Same business rules as the `/scan` API.

The optional `source` parameter must be one of: `clamav` · `virustotal` · `admin` · `threat-feed` · `manual`. Defaults to `clamav` if omitted. An unrecognised value returns a `400` error:

```
error=unknown source: typo (valid: clamav, virustotal, admin, threat-feed, manual)
```

### Check before scanning

```
GET /simple/check?sha256=<hash>&pattern=<version>&source=<src>
```

```bash
curl -s "http://localhost:8080/simple/check?\
sha256=a3f1c2d4e5b6789012345678901234567890123456789012345678901234abcd\
&pattern=daily.cvd:26843\
&source=clamav"
```

**Response — pattern outdated, rescan needed:**

```
recommend=rescan
reason=pattern outdated (stored: daily.cvd:26800, current: daily.cvd:26843)
sha256=a3f1c2d4e5b6789012345678901234567890123456789012345678901234abcd
status=clean
action=allow
firstSeen=2026-03-25T12:00:00Z
lastSeen=2026-03-25T14:00:00Z
fileName=invoice.pdf
fileName=order_confirmation.pdf
source=clamav
pattern=daily.cvd:26800
```

`recommend` is the scan decision (`scan` / `skip` / `rescan`). `action` is the stored policy from the record (`allow` / `block` / …). These are distinct fields with different key names to avoid ambiguity.


### Report clean

```
GET /simple/clean?sha256=<hash>&pattern=<version>&source=<src>&fileName=<name>&note=<text>
```

```bash
curl -s "http://localhost:8080/simple/clean?\
sha256=a3f1c2d4e5b6789012345678901234567890123456789012345678901234abcd\
&pattern=daily.cvd:26843\
&source=clamav\
&fileName=invoice.pdf\
&note=no+threats+found"
```

**Response:**

```
stored=true
reason=clean result recorded
sha256=a3f1c2d4e5b6789012345678901234567890123456789012345678901234abcd
status=clean
action=allow
firstSeen=2026-03-25T12:00:00Z
lastSeen=2026-03-25T14:05:00Z
source=clamav
pattern=daily.cvd:26843
```


### Report infected

```
GET /simple/infected?sha256=<hash>&pattern=<version>&source=<src>&threat=<name>&fileName=<name>&note=<text>
```

```bash
curl -s "http://localhost:8080/simple/infected?\
sha256=131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267\
&pattern=daily.cvd:26843\
&source=clamav\
&threat=Eicar-Signature\
&fileName=eicar.com\
&note=ClamAV+1.4"
```

**Response:**

```
stored=true
reason=infected result recorded
sha256=131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267
status=infected
action=block
firstSeen=2026-03-25T14:04:00Z
lastSeen=2026-03-25T14:05:00Z
threat=Eicar-Signature
source=clamav
pattern=daily.cvd:26843
note=ClamAV 1.4
```


### One-word status

```
GET /simple/status?sha256=<hash>
```

Returns a single word on one line: `clean`, `infected`, `quarantined`, `error`, or `unknown`.

```bash
curl -s "http://localhost:8080/simple/status?\
sha256=131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267"
```

**Response:**

```
infected
```


## Auth endpoint — `/auth`

Compatible with **nginx `auth_request`**. No body. Scan result and metadata are returned as `X-Scan-*` response headers. The HTTP status code drives the allow/block decision.

```
GET /auth?sha256=<hash>
```

| HTTP status | `X-Scan-Action` | Meaning                              |
|-------------|-----------------|--------------------------------------|
| `200 OK`    | `allow`         | File is clean — let it through       |
| `200 OK`    | `scan`          | Not seen before — scan before decide |
| `403 Forbidden` | `block`     | Infected or quarantined — block      |

```bash
# check a known-infected file
curl -si "http://localhost:8080/auth?\
sha256=131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267"
```

**Response — infected (`403`):**

```
HTTP/1.1 403 Forbidden
X-Scan-Status:     infected
X-Scan-Action:     block
X-Scan-SHA256:     131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267
X-Scan-FirstSeen:  2026-03-25T14:04:00Z
X-Scan-LastSeen:   2026-03-25T14:05:00Z
X-Scan-FileName:   eicar.com, eicar.txt
X-Scan-Threat:     Eicar-Signature
X-Scan-Source:     clamav
X-Scan-Pattern:    daily.cvd:26843
X-Scan-Note:       ClamAV 1.4

infected
```

```bash
# check a clean file
curl -si "http://localhost:8080/auth?\
sha256=a3f1c2d4e5b6789012345678901234567890123456789012345678901234abcd"
```

**Response — clean (`200`):**

```
HTTP/1.1 200 OK
X-Scan-Status:    clean
X-Scan-Action:    allow
X-Scan-SHA256:    a3f1c2d4e5b6789012345678901234567890123456789012345678901234abcd
X-Scan-FirstSeen: 2026-03-25T12:00:00Z
X-Scan-LastSeen:  2026-03-25T14:05:00Z
X-Scan-FileName:  invoice.pdf
X-Scan-Source:    clamav
X-Scan-Pattern:   daily.cvd:26843

clean
```

```bash
# check an unknown file — not yet in the database
curl -si "http://localhost:8080/auth?sha256=0000000000000000000000000000000000000000000000000000000000000001"
```

**Response — not seen before (`200`, but action=scan):**

```
HTTP/1.1 200 OK
X-Scan-Action: scan
X-Scan-Status: unknown

unknown
```

Timestamps in headers are rendered as RFC-3339 strings. The underlying storage is Unix epoch `int64`.

### nginx `auth_request` example

```nginx
location /mail-attachment {
    auth_request /auth-check;
    # on allow: proxy to mail handler
}

location = /auth-check {
    internal;
    proxy_pass http://open-filerep:8080/auth?sha256=$arg_sha256;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
}
```


## Utility endpoints

### Health check

```
GET /health
```

```bash
curl -s http://localhost:8080/health
```

**Response `200 OK`:**

```json
{ "status": "ok" }
```


### Metrics

```
GET /metrics
```

Prometheus text format — no external scrape configuration required beyond default labels.

```bash
curl -s http://localhost:8080/metrics
```

**Response:**

```
# HELP open_filerep_uptime_seconds Seconds since the process started
# TYPE open_filerep_uptime_seconds gauge
open_filerep_uptime_seconds 42.317

# HELP open_filerep_records_total Total number of file records in the database
# TYPE open_filerep_records_total gauge
open_filerep_records_total 3

# HELP open_filerep_records_by_status Number of records per scan status
# TYPE open_filerep_records_by_status gauge
open_filerep_records_by_status{status="clean"}       2
open_filerep_records_by_status{status="infected"}    1
open_filerep_records_by_status{status="quarantined"} 0
open_filerep_records_by_status{status="unknown"}     0
open_filerep_records_by_status{status="error"}       0

# HELP open_filerep_http_requests_total HTTP requests handled since start
# TYPE open_filerep_http_requests_total counter
open_filerep_http_requests_total{operation="add"}              3
open_filerep_http_requests_total{operation="list"}             2
open_filerep_http_requests_total{operation="get"}              1
open_filerep_http_requests_total{operation="update"}           1
open_filerep_http_requests_total{operation="delete"}           0
open_filerep_http_requests_total{operation="scan_check"}       5
open_filerep_http_requests_total{operation="scan_clean"}       4
open_filerep_http_requests_total{operation="scan_infected"}    1
open_filerep_http_requests_total{operation="simple_check"}     0
open_filerep_http_requests_total{operation="simple_clean"}     0
open_filerep_http_requests_total{operation="simple_infected"}  0
open_filerep_http_requests_total{operation="simple_status"}    0
open_filerep_http_requests_total{operation="auth"}             2
open_filerep_http_requests_total{operation="admin_backup"}     1
```


## Typical ClamAV Milter flow

```
1.  Mail arrives with attachment — compute SHA-256

2.  GET /scan/{sha256}?pattern=daily.cvd:26843
        action=scan    → not seen before, proceed with scan
        action=skip    → already infected: reject mail immediately
                         already clean with same pattern: accept
                         whitelisted by admin: accept regardless of scanner history
        action=rescan  → clean but outdated pattern: scan again

3a. ClamAV: no threat
        POST /scan/clean  { sha256, fileName, pattern, source:"clamav" }
        → record: status=clean, action=allow, firstSeen/lastSeen set

3b. ClamAV: threat found
        POST /scan/infected { sha256, fileName, pattern, threat, source:"clamav" }
        → record: status=infected, action=block, threat=<threat>
        → reject / quarantine mail

4.  Optional: /auth?sha256=<hash> for nginx auth_request integration
        HTTP 200 + X-Scan-Action: allow   → let through
        HTTP 403 + X-Scan-Action: block   → block
```


## Container image

### Pull and run

```bash
docker run -d \
  --name open-filerep \
  -p 8080:8080 \
  -v open-filerep-data:/data \
  ghcr.io/nashcom/open-filerep:latest
```

The database is stored in the `/data` volume. The service starts immediately — no configuration file required.

### docker-compose

```yaml
services:
  open-filerep:
    image: ghcr.io/nashcom/open-filerep:latest
    ports:
      - "8080:8080"
    volumes:
      - open-filerep-data:/data
    environment:
      FILEREP_LOG_LEVEL: info
      FILEREP_BACKUP_DIR: /data/backups
      FILEREP_BACKUP_INTERVAL: 24h
      FILEREP_BACKUP_KEEP: "7"
      FILEREP_BACKUP_GZIP: "true"
    restart: unless-stopped

volumes:
  open-filerep-data:
```

### Build the container image

```bash
./build.sh
```

Builds `nashcom/open-filerep:latest` using `container/Dockerfile`. Override the image name with `-image`:

```bash
./build.sh -image myregistry/open-filerep
```

### Compile locally without a local Go installation

```bash
./compile.sh
# output: bin/open-filerep  (Linux x86-64)
```

Uses `golang:alpine` via Docker. No local Go toolchain required.


## Building from source

### Windows

```bat
build.bat
```

### Linux / WSL

```bash
cd src
go build -o ../open-filerep .
```


## Running

```
open-filerep: version   : 0.9.7  commit: abc1234
open-filerep: database  : ./data
open-filerep: listening : :8080
open-filerep: log-level : info
```

The Badger database is created in the `./data` subdirectory (or `/data` in the container). No configuration file is needed.

### Configuration

All settings can be provided as **environment variables** or **command-line flags**. CLI flags take priority over environment variables.

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--db` | `FILEREP_DB` | `./data` | Path to the Badger database directory |
| `--port` | `FILEREP_PORT` | `:8080` | Listen address (e.g. `:9090`, `127.0.0.1:8080`) |
| `--log-level` | `FILEREP_LOG_LEVEL` | `info` | Log verbosity: `error` \| `info` \| `debug` |
| `--backup` | — | — | Write a full backup to `file` (use `-` for stdout) then exit |
| `--restore` | — | — | Restore from `file` (use `-` for stdin) then exit |
| `--backup-dir` | `FILEREP_BACKUP_DIR` | — | Directory for scheduled local backups |
| `--backup-interval` | `FILEREP_BACKUP_INTERVAL` | `24h` | Interval between scheduled backups (e.g. `6h`, `24h`) |
| `--backup-keep` | `FILEREP_BACKUP_KEEP` | `7` | Number of scheduled backup files to keep (0 = keep all) |
| `--backup-gzip` | `FILEREP_BACKUP_GZIP` | `false` | Gzip-compress backup files (`true` \| `1` \| `yes`) |

### Log levels

| Level | What is logged |
|-------|---------------|
| `error` | Fatal errors only |
| `info` | Startup, wipe, backup complete/prune *(default)* |
| `debug` | Everything above plus every ADD, UPD, DEL, SCAN, and SIMPLE request |

```bash
open-filerep --log-level debug    # trace every request
open-filerep --log-level error    # silent except fatal errors
```


## Tests

```bash
chmod +x test.sh examples.sh
./test.sh       # smoke test: clean + infected lifecycle, metrics, cleanup
./examples.sh   # annotated curl walkthrough
```

Requires `curl` and `jq`.


## Backup and restore

### HTTP streaming backup (service running)

```
GET /admin/backup
```

Streams a full binary dump to the caller as `application/octet-stream`. The service stays up — no downtime. The caller decides what to do with the bytes.

**Do not compress before sending to borg** — borg compresses and deduplicates internally. Pre-compressing breaks chunk-level deduplication.

```bash
# write to a local file (uncompressed)
curl -s http://localhost:8080/admin/backup > db.dump

# write to a local file (gzip-compressed)
curl -s http://localhost:8080/admin/backup | gzip > db.dump.gz

# pipe directly into borg (uncompressed — borg handles compression and dedup)
curl -s http://localhost:8080/admin/backup | borg create --stdin-name db.dump /var/backups/borg::db-$(date +%F) -
```


### Scheduled local backups (service running)

Start the service with `--backup-dir` to enable automatic periodic backups:

```bash
# uncompressed daily backups, keep 7
open-filerep --backup-dir /var/backups/open-filerep --backup-interval 24h --backup-keep 7

# gzip-compressed, keep 14
open-filerep --backup-dir /var/backups/open-filerep --backup-interval 24h --backup-keep 14 --backup-gzip
```

| Flag | Default | Description |
|------|---------|-------------|
| `--backup-dir` | *(disabled)* | Directory to write backup files into |
| `--backup-interval` | `24h` | How often to write a backup (e.g. `6h`, `24h`) |
| `--backup-keep` | `7` | How many files to keep; oldest are pruned (0 = keep all) |
| `--backup-gzip` | `false` | Gzip-compress backup files (saved as `.dump.gz`, ~40–55% smaller) |

Files are named `open-filerep-2026-03-25T14-05-00Z.dump` (or `.dump.gz`). ISO timestamps sort lexicographically so pruning always removes the oldest. Mixed `.dump` and `.dump.gz` files in the same directory are pruned together correctly.


### Emergency offline backup / restore (service stopped)

These modes open the database directly. They will **fail with a lock error** if the service is running — use the HTTP endpoint instead.

The file extension controls compression automatically: `.dump` = plain, `.dump.gz` = gzip.
`--backup-gzip` also works here — if the filename doesn't already end in `.gz` it is appended automatically.

```bash
# backup to a plain file
open-filerep --backup /var/backups/emergency.dump

# backup to a gzip-compressed file
open-filerep --backup /var/backups/emergency.dump.gz

# backup to stdout — pipe to borg or gzip yourself
open-filerep --backup - | borg create --stdin-name db.dump repo::archive -
open-filerep --backup - | gzip > /var/backups/emergency.dump.gz

# restore from a plain file (wipes the database first, then loads)
open-filerep --restore /var/backups/emergency.dump

# restore from a gzip-compressed file
open-filerep --restore /var/backups/emergency.dump.gz

# restore from stdin (e.g. from borg)
borg extract --stdout repo::archive db.dump | open-filerep --restore -
```


## Disk maintenance

Badger runs a value-log garbage collector automatically every 5 minutes in a background goroutine. No manual compaction is needed for normal workloads.


## Dependencies

| Package | Version |
|---------|---------|
| [dgraph-io/badger/v4](https://github.com/dgraph-io/badger) | v4.3.0 |
| Go | 1.22+ |
