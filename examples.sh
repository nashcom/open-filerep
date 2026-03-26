#!/bin/bash
# open-filerep — curl examples
# Requires: curl, jq
# Start the server first: ./open-filerep

BASE="http://localhost:8080"

# Real-ish SHA-256 hashes for the examples
SHA_PDF="3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f607182930a1b2c3d4"
SHA_DOC="a1b2c3d4e5f60718293041526374859607182930a1b2c3d4e5f6071829304152"
SHA_PNG="f0e1d2c3b4a5968778695a4b3c2d1e0f9081726354a5b6c7d8e9f0a1b2c3d4e5"

# Actual SHA-256 of the EICAR standard antivirus test file
# echo -n 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' | sha256sum
SHA_EICAR="131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267"

header() { echo; echo "─── $* ───"; }

# ---------------------------------------------------------------------------
header "Health check"
# ---------------------------------------------------------------------------
curl -s "$BASE/health" | jq .

# ---------------------------------------------------------------------------
header "Add three file records"
# ---------------------------------------------------------------------------
curl -s -X POST "$BASE/files" \
  -H "Content-Type: application/json" \
  -d "{
    \"sha256\":   \"$SHA_PDF\",
    \"fileName\": \"invoice_2026.pdf\",
    \"status\":   \"unknown\",
    \"source\":   \"manual\",
    \"note\":     \"queued for ClamAV\"
  }" | jq .

curl -s -X POST "$BASE/files" \
  -H "Content-Type: application/json" \
  -d "{
    \"sha256\":   \"$SHA_DOC\",
    \"fileName\": \"contract_draft.docx\",
    \"status\":   \"clean\",
    \"action\":   \"allow\",
    \"source\":   \"clamav\",
    \"pattern\":  \"daily.cvd:26843\",
    \"note\":     \"no threats found\"
  }" | jq .

curl -s -X POST "$BASE/files" \
  -H "Content-Type: application/json" \
  -d "{
    \"sha256\":     \"$SHA_PNG\",
    \"fileName\":   \"logo.png\",
    \"status\":     \"infected\",
    \"action\":     \"block\",
    \"source\":     \"virustotal\",
    \"threat\":     \"Eicar-Test-Signature\",
    \"note\":       \"detected by VirusTotal\"
  }" | jq .

# ---------------------------------------------------------------------------
header "Query single record (PDF)"
# ---------------------------------------------------------------------------
curl -s "$BASE/files/$SHA_PDF" | jq .

# ---------------------------------------------------------------------------
header "List all records"
# ---------------------------------------------------------------------------
curl -s "$BASE/files" | jq .

# ---------------------------------------------------------------------------
header "List only infected records"
# ---------------------------------------------------------------------------
curl -s "$BASE/files?status=infected" | jq .

# ---------------------------------------------------------------------------
header "List only clean records"
# ---------------------------------------------------------------------------
curl -s "$BASE/files?status=clean" | jq .

# ---------------------------------------------------------------------------
header "Update PDF status to clean"
# ---------------------------------------------------------------------------
curl -s -X PUT "$BASE/files/$SHA_PDF" \
  -H "Content-Type: application/json" \
  -d '{
    "status":  "clean",
    "action":  "allow",
    "source":  "clamav",
    "pattern": "daily.cvd:26843",
    "note":    "no threats found"
  }' | jq .

# ---------------------------------------------------------------------------
header "Query updated record"
# ---------------------------------------------------------------------------
curl -s "$BASE/files/$SHA_PDF" | jq .

# ---------------------------------------------------------------------------
header "Infected file lifecycle — EICAR test file"
# ---------------------------------------------------------------------------

# Step 1: file arrives — check reputation before scanning
echo "  [1] Check before scan (not seen yet → action=scan)"
curl -s "$BASE/scan/$SHA_EICAR?pattern=daily.cvd:26843" | jq .

# Step 2: ClamAV returns a hit — report via scan API (enforces business rules)
echo "  [2] ClamAV reports infected"
curl -s -X POST "$BASE/scan/infected" \
  -H "Content-Type: application/json" \
  -d "{
    \"sha256\":     \"$SHA_EICAR\",
    \"fileName\":   \"eicar.com\",
    \"pattern\":    \"daily.cvd:26843\",
    \"threat\":     \"Eicar-Signature\",
    \"source\":     \"clamav\",
    \"note\":       \"ClamAV 1.4\"
  }" | jq .

# Step 3: mail system moves file to quarantine — update action via CRUD
echo "  [3] Move to quarantined"
curl -s -X PUT "$BASE/files/$SHA_EICAR" \
  -H "Content-Type: application/json" \
  -d '{
    "status": "quarantined",
    "action": "block",
    "note":   "moved to /var/quarantine by Milter"
  }' | jq .

# Step 4: verify final state
echo "  [4] Verify quarantined state"
curl -s "$BASE/files/$SHA_EICAR" | jq .

# Step 5: list quarantined — should contain the EICAR file
echo "  [5] List all quarantined"
curl -s "$BASE/files?status=quarantined" | jq .

# Step 6: list infected — should be empty now
echo "  [6] List all infected (should be empty)"
curl -s "$BASE/files?status=infected" | jq .

# ---------------------------------------------------------------------------
header "Metrics"
# ---------------------------------------------------------------------------
curl -s "$BASE/metrics"

# ---------------------------------------------------------------------------
header "Delete infected record"
# ---------------------------------------------------------------------------
curl -s -o /dev/null -w "HTTP %{http_code}\n" -X DELETE "$BASE/files/$SHA_PNG"

# ---------------------------------------------------------------------------
header "Confirm deletion (expect 404)"
# ---------------------------------------------------------------------------
curl -s "$BASE/files/$SHA_PNG" | jq .

# ---------------------------------------------------------------------------
header "Final metrics (counts should reflect deletes)"
# ---------------------------------------------------------------------------
curl -s "$BASE/metrics"
