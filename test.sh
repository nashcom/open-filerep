#!/bin/bash
# Smoke-test for open-filerep.
# Requires a running server — start it first:  ./open-filerep.exe  (or ./open-filerep)
# Override the base URL:  BASE=http://localhost:9090 ./test.sh
#
# The test calls DELETE /files at startup to wipe all records, so every run
# begins from a guaranteed clean slate regardless of leftover data.
#
# Covers: generic CRUD, scan API business rules, multi-source resolution,
#         fileNames accumulation, whitelist override, parameter validation,
#         backup endpoint.

BASE="${BASE:-http://localhost:8080}"

# ---------------------------------------------------------------------------
# Verify the server is reachable before starting
# ---------------------------------------------------------------------------
if ! curl -s -o /dev/null "$BASE/health" 2>/dev/null; then
    echo "ERROR: no server reachable at $BASE — start open-filerep first"
    exit 1
fi

# ---------------------------------------------------------------------------
# Wipe all records so every run starts from a clean slate.
# ---------------------------------------------------------------------------
curl -s -o /dev/null -X DELETE "$BASE/files"

SHA_CLEAN="a3f1c2d4e5b6789012345678901234567890123456789012345678901234abcd"
SHA_DOC="b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3"
SHA_SIMPLE="ccddee001122334455667788990011223344556677889900aabbccddeeff0011"
SHA_WHITELIST="ee00112233445566778899001122334455667788990011223344556677889900"
UNKNOWN="aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff0000aaaa1111bbbb2222"
SHA_MULTI="ddee0011223344556677889900aabbccddeeff00112233445566778899001122"
SHA_NAMES="ff00aabb1122ccdd3344eeff5566aabb7788ccdd9900eeff1122334455667788"

# Actual SHA-256 of the EICAR standard antivirus test file:
# echo -n 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' | sha256sum
SHA_EICAR="131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267"

PAT_OLD="daily.cvd:26800"
PAT_NEW="daily.cvd:26843"

PASS=0
FAIL=0

sep()  { echo; echo "━━━ $* ━━━"; }
info() { echo "  → $*"; }

# check "label" "<jq-expr>" "<json>"  "<expected>"   -- evaluate jq path against JSON body
# check "label" "<value>"   ""        "<expected>"   -- direct string compare (szJSON empty)
# check "label" ""          "<value>" "<expected>"   -- direct string compare (szExpr empty)
check() {
    local szLabel="$1"
    local szExpr="$2"
    local szJSON="$3"
    local szExpected="$4"
    local szResult

    if [ -z "$szJSON" ]; then
        szResult="$szExpr"
    elif [ -z "$szExpr" ]; then
        szResult="$szJSON"
    else
        szResult=$(echo "$szJSON" | jq -r "$szExpr" 2>/dev/null)
    fi

    if [ "$szResult" = "true" ] || [ "$szResult" = "$szExpected" ]; then
        echo "  [PASS] $szLabel"
        PASS=$((PASS + 1))
    else
        echo "  [FAIL] $szLabel  (got: $szResult)"
        FAIL=$((FAIL + 1))
    fi
}

# ============================================================================
sep "Health"
# ============================================================================
RES=$(curl -s "$BASE/health")
check "health status=ok"       '.status == "ok"'           "$RES" "true"
check "health version present" '.version | length > 0'     "$RES" "true"
info "version: $(echo "$RES" | jq -r '.version')"

# ============================================================================
sep "CRUD — clean file lifecycle"
# ============================================================================
info "POST clean file"
RES=$(curl -s -X POST "$BASE/files" \
  -H "Content-Type: application/json" \
  -d "{\"sha256\":\"$SHA_CLEAN\",\"fileName\":\"invoice.pdf\",\"source\":\"admin\",\"status\":\"clean\",\"pattern\":\"$PAT_OLD\",\"note\":\"initial\"}")
check "add: effectiveStatus=clean"  '.effectiveStatus == "clean"'        "$RES" "true"
check "add: sources[0].pattern"     ".sources[0].pattern == \"$PAT_OLD\"" "$RES" "true"

info "PUT update note"
RES=$(curl -s -X PUT "$BASE/files/$SHA_CLEAN" \
  -H "Content-Type: application/json" \
  -d "{\"note\":\"updated note\"}")
check "update: note updated"          '.note == "updated note"'        "$RES" "true"
check "update: effectiveStatus clean" '.effectiveStatus == "clean"'    "$RES" "true"

info "GET the record"
RES=$(curl -s "$BASE/files/$SHA_CLEAN")
check "get: correct sha256" ".sha256 == \"$SHA_CLEAN\"" "$RES" "true"

info "DELETE"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "$BASE/files/$SHA_CLEAN")
check "delete: 204" "" "$CODE" "204"

info "GET after delete"
CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/files/$SHA_CLEAN")
check "get after delete: 404" "" "$CODE" "404"

# ============================================================================
sep "CRUD — fileSize tracking"
# ============================================================================
info "POST /files with fileSize"
RES=$(curl -s -X POST "$BASE/files" \
  -H "Content-Type: application/json" \
  -d "{\"sha256\":\"$SHA_CLEAN\",\"fileName\":\"report.pdf\",\"fileSize\":45829,\"source\":\"admin\",\"status\":\"clean\"}")
check "add with fileSize: fileSize stored" '.fileSize == 45829' "$RES" "true"
check "add with fileSize: sources[0].fileSize" '.sources[0].fileSize == 45829' "$RES" "true"

info "PUT update fileSize"
RES=$(curl -s -X PUT "$BASE/files/$SHA_CLEAN" \
  -H "Content-Type: application/json" \
  -d "{\"fileSize\":50000}")
check "PUT fileSize: fileSize updated" '.fileSize == 50000' "$RES" "true"

info "POST /scan/clean with fileSize"
RES=$(curl -s -X POST "$BASE/scan/clean" \
  -H "Content-Type: application/json" \
  -d "{\"sha256\":\"$SHA_DOC\",\"fileName\":\"document.docx\",\"fileSize\":123456,\"pattern\":\"$PAT_NEW\",\"source\":\"clamav\"}")
check "scan/clean with fileSize: stored" '.stored == true' "$RES" "true"
check "scan/clean with fileSize: record.fileSize" '.record.fileSize == 123456' "$RES" "true"
check "scan/clean with fileSize: source.fileSize" '.record.sources[0].fileSize == 123456' "$RES" "true"

info "POST /scan/infected with fileSize"
RES=$(curl -s -X POST "$BASE/scan/infected" \
  -H "Content-Type: application/json" \
  -d "{\"sha256\":\"$SHA_EICAR\",\"fileName\":\"eicar.com\",\"fileSize\":68,\"pattern\":\"$PAT_NEW\",\"threat\":\"Eicar-Signature\"}")
check "scan/infected with fileSize: fileSize stored" '.record.fileSize == 68' "$RES" "true"
check "scan/infected with fileSize: source.fileSize" '.record.sources[0].fileSize == 68' "$RES" "true"

info "GET /simple/clean with fileSize"
RES=$(curl -s "$BASE/simple/clean?sha256=$SHA_SIMPLE&pattern=$PAT_NEW&fileSize=99999&source=clamav")
check "simple/clean fileSize param accepted" "" "$(echo "$RES" | grep 'fileSize=99999')" "fileSize=99999"

info "GET /simple/infected with fileSize"
RES=$(curl -s "$BASE/simple/infected?sha256=$SHA_WHITELIST&pattern=$PAT_NEW&fileSize=54321&threat=Malware.Test&source=clamav")
check "simple/infected fileSize param accepted" "" "$(echo "$RES" | grep 'fileSize=54321')" "fileSize=54321"

curl -s -o /dev/null -X DELETE "$BASE/files/$SHA_CLEAN"
curl -s -o /dev/null -X DELETE "$BASE/files/$SHA_DOC"
curl -s -o /dev/null -X DELETE "$BASE/files/$SHA_EICAR"
curl -s -o /dev/null -X DELETE "$BASE/files/$SHA_SIMPLE"
curl -s -o /dev/null -X DELETE "$BASE/files/$SHA_WHITELIST"

# ============================================================================
sep "Validation — unknown JSON fields rejected"
# ============================================================================
info "POST /files with unknown JSON field"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/files" \
  -H "Content-Type: application/json" \
  -d "{\"sha256\":\"$SHA_CLEAN\",\"status\":\"clean\",\"source\":\"admin\",\"notAField\":\"oops\"}")
check "unknown JSON field: 400" "" "$CODE" "400"

info "PUT /files with unknown JSON field"
curl -s -X POST "$BASE/files" -H "Content-Type: application/json" \
  -d "{\"sha256\":\"$SHA_CLEAN\",\"status\":\"clean\",\"source\":\"admin\"}" > /dev/null
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "$BASE/files/$SHA_CLEAN" \
  -H "Content-Type: application/json" \
  -d "{\"note\":\"ok\",\"badField\":\"oops\"}")
check "unknown JSON field PUT: 400" "" "$CODE" "400"
curl -s -o /dev/null -X DELETE "$BASE/files/$SHA_CLEAN"

info "POST /scan/clean with unknown JSON field"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/scan/clean" \
  -H "Content-Type: application/json" \
  -d "{\"sha256\":\"$SHA_CLEAN\",\"unknownField\":\"oops\"}")
check "unknown JSON field scan/clean: 400" "" "$CODE" "400"

# ============================================================================
sep "Validation — unknown query parameters rejected"
# ============================================================================
info "GET /simple/check with unknown param"
CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  "$BASE/simple/check?sha256=$SHA_CLEAN&pattern=$PAT_NEW&typo=oops")
check "unknown query param simple/check: 400" "" "$CODE" "400"

info "GET /simple/infected with misspelled threat param"
CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  "$BASE/simple/infected?sha256=$SHA_CLEAN&threet=Trojan.Test")
check "misspelled param simple/infected: 400" "" "$CODE" "400"

info "GET /simple/status with extra param"
CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  "$BASE/simple/status?sha256=$SHA_CLEAN&extra=oops")
check "extra param simple/status: 400" "" "$CODE" "400"

info "GET /simple/clean with unknown param"
CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  "$BASE/simple/clean?sha256=$SHA_CLEAN&pattern=$PAT_NEW&foo=bar")
check "unknown param simple/clean: 400" "" "$CODE" "400"

info "GET /auth with extra param"
CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  "$BASE/auth?sha256=$SHA_CLEAN&extra=oops")
check "extra param auth: 400" "" "$CODE" "400"

info "GET /files with unknown filter"
CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  "$BASE/files?statuss=clean")
check "unknown param list: 400" "" "$CODE" "400"

# ============================================================================
sep "Scan API — unknown file (action=scan)"
# ============================================================================
info "GET /scan/{sha256} for unseen file"
RES=$(curl -s "$BASE/scan/$SHA_CLEAN?pattern=$PAT_NEW")
check "scan check: action=scan" '.action == "scan"' "$RES" "true"
check "scan check: record=null" '.record == null'   "$RES" "true"

# ============================================================================
sep "Scan API — report clean, then check same pattern (skip)"
# ============================================================================
info "POST /scan/clean with $PAT_NEW"
RES=$(curl -s -X POST "$BASE/scan/clean" \
  -H "Content-Type: application/json" \
  -d "{\"sha256\":\"$SHA_CLEAN\",\"fileName\":\"invoice.pdf\",\"pattern\":\"$PAT_NEW\",\"note\":\"no threats\"}")
check "scan/clean: stored=true"              '.stored == true'                              "$RES" "true"
check "scan/clean: effectiveStatus=clean"    '.record.effectiveStatus == "clean"'           "$RES" "true"
check "scan/clean: effectiveAction=allow"    '.record.effectiveAction == "allow"'           "$RES" "true"
check "scan/clean: sources[0].source=clamav" '.record.sources[0].source == "clamav"'       "$RES" "true"
check "scan/clean: sources[0].pattern saved" ".record.sources[0].pattern == \"$PAT_NEW\""  "$RES" "true"
check "scan/clean: firstSeen set"            '.record.firstSeen > 0'                       "$RES" "true"
check "scan/clean: lastSeen set"             '.record.lastSeen > 0'                        "$RES" "true"

info "GET /scan/{sha256}?pattern=$PAT_NEW  (same pattern → skip)"
RES=$(curl -s "$BASE/scan/$SHA_CLEAN?pattern=$PAT_NEW")
check "same pattern: action=skip" '.action == "skip"' "$RES" "true"

# ============================================================================
sep "Scan API — older pattern triggers rescan"
# ============================================================================
info "GET /scan/{sha256}?pattern=$PAT_OLD  (older than stored $PAT_NEW → rescan)"
RES=$(curl -s "$BASE/scan/$SHA_CLEAN?pattern=$PAT_OLD")
check "old pattern: action=rescan" '.action == "rescan"' "$RES" "true"

# ============================================================================
sep "Scan API — clean does NOT overwrite infected"
# ============================================================================
info "POST /scan/infected  (mark file infected)"
RES=$(curl -s -X POST "$BASE/scan/infected" \
  -H "Content-Type: application/json" \
  -d "{\"sha256\":\"$SHA_CLEAN\",\"fileName\":\"invoice.pdf\",\"pattern\":\"$PAT_NEW\",\"threat\":\"Trojan.Fake-Invoice\"}")
check "scan/infected: stored=true"              '.stored == true'                                       "$RES" "true"
check "scan/infected: effectiveStatus=infected" '.record.effectiveStatus == "infected"'                "$RES" "true"
check "scan/infected: threat set"               '.record.sources[0].threat == "Trojan.Fake-Invoice"'   "$RES" "true"
check "scan/infected: effectiveAction=block"    '.record.effectiveAction == "block"'                   "$RES" "true"
check "scan/infected: sources[0].source=clamav" '.record.sources[0].source == "clamav"'               "$RES" "true"

info "POST /scan/clean after infected  (must be rejected)"
RES=$(curl -s -X POST "$BASE/scan/clean" \
  -H "Content-Type: application/json" \
  -d "{\"sha256\":\"$SHA_CLEAN\",\"fileName\":\"invoice.pdf\",\"pattern\":\"$PAT_NEW\",\"note\":\"false positive?\"}")
check "clean after infected: stored=false"   '.stored == false'                       "$RES" "true"
check "clean after infected: still infected" '.record.effectiveStatus == "infected"'  "$RES" "true"

info "GET /scan/{sha256}  (infected → always skip)"
RES=$(curl -s "$BASE/scan/$SHA_CLEAN?pattern=$PAT_NEW")
check "infected: action=skip" '.action == "skip"' "$RES" "true"

# ============================================================================
sep "Scan API — EICAR full lifecycle"
# ============================================================================
info "Check EICAR before first scan"
RES=$(curl -s "$BASE/scan/$SHA_EICAR?pattern=$PAT_NEW")
check "eicar pre-check: action=scan" '.action == "scan"' "$RES" "true"

info "POST /scan/infected for EICAR"
RES=$(curl -s -X POST "$BASE/scan/infected" \
  -H "Content-Type: application/json" \
  -d "{\"sha256\":\"$SHA_EICAR\",\"fileName\":\"eicar.com\",\"pattern\":\"$PAT_NEW\",\"threat\":\"Eicar-Signature\",\"note\":\"ClamAV 1.4\"}")
check "eicar: stored=true"              '.stored == true'                                  "$RES" "true"
check "eicar: effectiveStatus=infected" '.record.effectiveStatus == "infected"'            "$RES" "true"
check "eicar: effectiveAction=block"    '.record.effectiveAction == "block"'               "$RES" "true"
check "eicar: threat set"               '.record.sources[0].threat == "Eicar-Signature"'  "$RES" "true"
check "eicar: firstSeen set"            '.record.firstSeen > 0'                           "$RES" "true"

info "POST /scan/clean for EICAR  (infected already — must lose)"
RES=$(curl -s -X POST "$BASE/scan/clean" \
  -H "Content-Type: application/json" \
  -d "{\"sha256\":\"$SHA_EICAR\",\"pattern\":\"$PAT_NEW\"}")
check "eicar clean rejected: stored=false"    '.stored == false'                       "$RES" "true"
check "eicar clean rejected: still infected"  '.record.effectiveStatus == "infected"'  "$RES" "true"

info "POST /scan/infected again  (should still update)"
RES=$(curl -s -X POST "$BASE/scan/infected" \
  -H "Content-Type: application/json" \
  -d "{\"sha256\":\"$SHA_EICAR\",\"fileName\":\"eicar.com\",\"pattern\":\"$PAT_NEW\",\"threat\":\"Eicar-Signature\",\"note\":\"re-confirmed\"}")
check "eicar re-infected: stored=true" '.stored == true' "$RES" "true"

# ============================================================================
sep "fileNames — accumulation and dedup"
# ============================================================================
# Use POST /files (pure CRUD, no business rules) so both names are stored
# regardless of infected/clean state.
info "POST /files with first fileName (evil.exe)"
curl -s -X POST "$BASE/files" -H "Content-Type: application/json" \
  -d "{\"sha256\":\"$SHA_NAMES\",\"fileName\":\"evil.exe\",\"status\":\"infected\",\"source\":\"clamav\",\"threat\":\"Trojan.Test\"}" > /dev/null

info "POST /files with second fileName (malware.dll) — different source"
curl -s -X POST "$BASE/files" -H "Content-Type: application/json" \
  -d "{\"sha256\":\"$SHA_NAMES\",\"fileName\":\"malware.dll\",\"status\":\"infected\",\"source\":\"virustotal\",\"threat\":\"Trojan.Test\"}" > /dev/null

info "GET — both names must be present"
RES=$(curl -s "$BASE/files/$SHA_NAMES")
check "fileNames: has 2 names"         '(.fileNames | length) == 2'                  "$RES" "true"
check "fileNames: evil.exe present"    '(.fileNames | contains(["evil.exe"]))'        "$RES" "true"
check "fileNames: malware.dll present" '(.fileNames | contains(["malware.dll"]))'     "$RES" "true"

info "POST /files same fileName again — must not duplicate"
curl -s -X POST "$BASE/files" -H "Content-Type: application/json" \
  -d "{\"sha256\":\"$SHA_NAMES\",\"fileName\":\"evil.exe\",\"status\":\"infected\",\"source\":\"threat-feed\"}" > /dev/null
RES=$(curl -s "$BASE/files/$SHA_NAMES")
check "fileNames: still 2 after duplicate" '(.fileNames | length) == 2' "$RES" "true"

info "Simple infected adds a third name (dropper.bat)"
curl -s "$BASE/simple/infected?sha256=$SHA_NAMES&threat=Trojan.Test&fileName=dropper.bat&pattern=$PAT_NEW" > /dev/null
RES=$(curl -s "$BASE/files/$SHA_NAMES")
check "fileNames: 3 names after simple infected"   '(.fileNames | length) == 3'                  "$RES" "true"
check "fileNames: dropper.bat present"             '(.fileNames | contains(["dropper.bat"]))'     "$RES" "true"

# ============================================================================
sep "Whitelist — admin override beats scanner results"
# ============================================================================
info "Seed an infected record"
curl -s -X POST "$BASE/scan/infected" -H "Content-Type: application/json" \
  -d "{\"sha256\":\"$SHA_WHITELIST\",\"fileName\":\"deploy-tool.exe\",\"threat\":\"Heuristic.Suspicious\",\"pattern\":\"$PAT_OLD\",\"source\":\"clamav\"}" > /dev/null

info "Verify it is infected before whitelist"
RES=$(curl -s "$BASE/files/$SHA_WHITELIST")
check "pre-whitelist: effectiveStatus=infected" '.effectiveStatus == "infected"' "$RES" "true"

info "POST /files with action=whitelist (admin override)"
RES=$(curl -s -X POST "$BASE/files" -H "Content-Type: application/json" \
  -d "{\"sha256\":\"$SHA_WHITELIST\",\"fileName\":\"deploy-tool.exe\",\"status\":\"clean\",\"action\":\"whitelist\",\"source\":\"admin\",\"note\":\"approved by ops\"}")
check "whitelist add: effectiveAction=whitelist"  '.effectiveAction == "whitelist"'  "$RES" "true"
check "whitelist add: effectiveStatus=clean"      '.effectiveStatus == "clean"'      "$RES" "true"
check "whitelist add: resolvedBy=admin"           '.resolvedBy == "admin"'           "$RES" "true"

info "GET /scan/{sha256} — must return skip (not rescan or scan)"
RES=$(curl -s "$BASE/scan/$SHA_WHITELIST?pattern=$PAT_NEW")
check "whitelist scan check: action=skip"             '.action == "skip"'             "$RES" "true"
check "whitelist scan check: reason=whitelisted"      '.reason | test("whitelisted")' "$RES" "true"

info "POST /scan/infected — scanner cannot override whitelist"
RES=$(curl -s -X POST "$BASE/scan/infected" -H "Content-Type: application/json" \
  -d "{\"sha256\":\"$SHA_WHITELIST\",\"threat\":\"Ransom.Sneaky\",\"pattern\":\"$PAT_NEW\",\"source\":\"virustotal\"}")
check "whitelist holds vs infected: stored=true"           '.stored == true'              "$RES" "true"
check "whitelist holds vs infected: effectiveAction=whitelist" '.record.effectiveAction == "whitelist"' "$RES" "true"
check "whitelist holds vs infected: effectiveStatus=clean" '.record.effectiveStatus == "clean"' "$RES" "true"

info "GET /auth — must return 200 + X-Scan-Action: whitelist"
CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/auth?sha256=$SHA_WHITELIST")
check "whitelist auth: HTTP 200"           "" "$CODE" "200"

ACTION=$(curl -s -D - -o /dev/null "$BASE/auth?sha256=$SHA_WHITELIST" \
    | grep -i '^X-Scan-Action:' | tr -d '\r' | awk '{print $2}')
check "whitelist auth: X-Scan-Action=whitelist" "" "$ACTION" "whitelist"

info "Verify sources still contain the virustotal infected entry"
RES=$(curl -s "$BASE/files/$SHA_WHITELIST")
check "whitelist: sources has 2 entries" '(.sources | length) >= 2' "$RES" "true"

info "DELETE — removes whitelist"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "$BASE/files/$SHA_WHITELIST")
check "whitelist delete: 204" "" "$CODE" "204"

info "After delete — file is unknown again (action=scan)"
RES=$(curl -s "$BASE/scan/$SHA_WHITELIST?pattern=$PAT_NEW")
check "post-delete: action=scan" '.action == "scan"' "$RES" "true"

# ============================================================================
sep "Simple API — /simple/check (text key=value response)"
# ============================================================================
PAT_S1="$PAT_OLD"
PAT_S2="$PAT_NEW"

info "Check unknown file → recommend=scan"
RES=$(curl -s "$BASE/simple/check?sha256=$SHA_SIMPLE&pattern=$PAT_S2")
check "simple check: recommend=scan" "$(echo "$RES" | grep '^recommend=' | cut -d= -f2)" "" "scan"

info "POST /scan/clean to seed the record"
curl -s -X POST "$BASE/scan/clean" -H "Content-Type: application/json" \
  -d "{\"sha256\":\"$SHA_SIMPLE\",\"fileName\":\"report.pdf\",\"pattern\":\"$PAT_S2\"}" > /dev/null

info "Check same pattern → skip"
RES=$(curl -s "$BASE/simple/check?sha256=$SHA_SIMPLE&pattern=$PAT_S2")
check "simple check same pattern: recommend=skip"   "$(echo "$RES" | grep '^recommend=' | cut -d= -f2)" "" "skip"

info "Check older pattern → rescan"
RES=$(curl -s "$BASE/simple/check?sha256=$SHA_SIMPLE&pattern=$PAT_S1")
check "simple check old pattern: recommend=rescan"  "$(echo "$RES" | grep '^recommend=' | cut -d= -f2)" "" "rescan"

# ============================================================================
sep "Simple API — /simple/status"
# ============================================================================
info "Status of clean file"
RES=$(curl -s "$BASE/simple/status?sha256=$SHA_SIMPLE" | tr -d '\n')
check "simple status: clean"   "" "$RES" "clean"

info "Status of unknown file"
RES=$(curl -s "$BASE/simple/status?sha256=$UNKNOWN" | tr -d '\n')
check "simple status: unknown" "" "$RES" "unknown"

# ============================================================================
sep "Simple API — /simple/infected  (infected beats clean)"
# ============================================================================
info "Report infected via simple API"
RES=$(curl -s "$BASE/simple/infected?sha256=$SHA_SIMPLE&pattern=$PAT_S2&threat=Trojan.TestSig&note=found+by+ClamAV")
check "simple infected: stored=true"     "$(echo "$RES" | grep '^stored='  | cut -d= -f2)" "" "true"
check "simple infected: status=infected" "$(echo "$RES" | grep '^status='  | cut -d= -f2)" "" "infected"
check "simple infected: action=block"    "$(echo "$RES" | grep '^action='  | cut -d= -f2)" "" "block"
check "simple infected: threat set"      "$(echo "$RES" | grep '^threat='  | cut -d= -f2)" "" "Trojan.TestSig"

info "Try clean after infected via simple API → must be rejected"
RES=$(curl -s "$BASE/simple/clean?sha256=$SHA_SIMPLE&pattern=$PAT_S2&note=false+positive")
check "simple clean after infected: stored=false"   "$(echo "$RES" | grep '^stored=' | cut -d= -f2)" "" "false"
check "simple clean after infected: still infected" "$(echo "$RES" | grep '^status=' | cut -d= -f2)" "" "infected"

info "Simple status after infected"
RES=$(curl -s "$BASE/simple/status?sha256=$SHA_SIMPLE" | tr -d '\n')
check "simple status after infected: infected" "" "$RES" "infected"

# ============================================================================
sep "Auth endpoint — /auth"
# ============================================================================
info "Auth for infected file → 403 + X-Scan-Action: block"
CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/auth?sha256=$SHA_SIMPLE")
check "auth infected: HTTP 403" "" "$CODE" "403"

HDRS=$(curl -s -D - -o /dev/null "$BASE/auth?sha256=$SHA_SIMPLE")
ACTION=$(echo "$HDRS"     | grep -i '^X-Scan-Action:' | tr -d '\r' | awk '{print $2}')
STATUS_HDR=$(echo "$HDRS" | grep -i '^X-Scan-Status:' | tr -d '\r' | awk '{print $2}')
THREAT=$(echo "$HDRS"     | grep -i '^X-Scan-Threat:'  | tr -d '\r' | awk '{print $2}')
SOURCE=$(echo "$HDRS"     | grep -i '^X-Scan-Source:'  | tr -d '\r' | awk '{print $2}')
FSEEN=$(echo "$HDRS"      | grep -i '^X-Scan-FirstSeen:' | tr -d '\r' | awk '{print $2}')

check "auth infected: X-Scan-Action=block"        "" "$ACTION"     "block"
check "auth infected: X-Scan-Status=infected"     "" "$STATUS_HDR" "infected"
check "auth infected: X-Scan-Threat set"          "" "$THREAT"     "Trojan.TestSig"
check "auth infected: X-Scan-Source set"          "" "$SOURCE"     "clamav"
check "auth infected: X-Scan-FirstSeen not empty" "" "$([ -n "$FSEEN" ] && echo yes || echo no)" "yes"

info "Auth for unknown file → 200 + X-Scan-Action: scan"
CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/auth?sha256=$UNKNOWN")
check "auth unknown: HTTP 200"           "" "$CODE" "200"
ACTION=$(curl -s -D - -o /dev/null "$BASE/auth?sha256=$UNKNOWN" \
    | grep -i '^X-Scan-Action:' | tr -d '\r' | awk '{print $2}')
check "auth unknown: X-Scan-Action=scan" "" "$ACTION" "scan"

info "Seed a clean file and check auth → 200 + allow"
curl -s -X POST "$BASE/scan/clean" -H "Content-Type: application/json" \
  -d "{\"sha256\":\"$UNKNOWN\",\"fileName\":\"clean.pdf\",\"pattern\":\"$PAT_S2\"}" > /dev/null
CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/auth?sha256=$UNKNOWN")
check "auth clean: HTTP 200"             "" "$CODE" "200"
ACTION=$(curl -s -D - -o /dev/null "$BASE/auth?sha256=$UNKNOWN" \
    | grep -i '^X-Scan-Action:' | tr -d '\r' | awk '{print $2}')
check "auth clean: X-Scan-Action=allow"  "" "$ACTION" "allow"

curl -s -o /dev/null -X DELETE "$BASE/files/$SHA_SIMPLE"
curl -s -o /dev/null -X DELETE "$BASE/files/$UNKNOWN"

# ============================================================================
sep "List / filter"
# ============================================================================
info "List all infected"
RES=$(curl -s "$BASE/files?status=infected")
check "list infected: ≥2 records" "length >= 2" "$RES" "true"

info "List clean (should be empty — all flipped to infected)"
RES=$(curl -s "$BASE/files?status=clean")
check "list clean: empty" "length == 0" "$RES" "true"

# ============================================================================
sep "Multi-source conflict resolution"
# ============================================================================
info "POST /scan/clean  source=clamav → stored, effectiveStatus=clean"
RES=$(curl -s -X POST "$BASE/scan/clean" -H "Content-Type: application/json" \
  -d "{\"sha256\":\"$SHA_MULTI\",\"fileName\":\"multi.exe\",\"source\":\"clamav\",\"pattern\":\"$PAT_NEW\"}")
check "multi clean1: stored=true"              '.stored == true'                    "$RES" "true"
check "multi clean1: effectiveStatus=clean"    '.record.effectiveStatus == "clean"' "$RES" "true"

info "POST /scan/infected source=virustotal → stored, effectiveStatus=infected"
RES=$(curl -s -X POST "$BASE/scan/infected" -H "Content-Type: application/json" \
  -d "{\"sha256\":\"$SHA_MULTI\",\"source\":\"virustotal\",\"threat\":\"Ransom.Multi\",\"pattern\":\"$PAT_NEW\"}")
check "multi infected: stored=true"              '.stored == true'                       "$RES" "true"
check "multi infected: effectiveStatus=infected" '.record.effectiveStatus == "infected"' "$RES" "true"

info "POST /scan/clean source=clamav again → effectiveStatus still infected"
RES=$(curl -s -X POST "$BASE/scan/clean" -H "Content-Type: application/json" \
  -d "{\"sha256\":\"$SHA_MULTI\",\"source\":\"clamav\",\"pattern\":\"$PAT_NEW\"}")
check "multi clean2: stored=false"                   '.stored == false'                       "$RES" "true"
check "multi clean2: effectiveStatus still infected" '.record.effectiveStatus == "infected"'  "$RES" "true"

info "GET /files/SHA_MULTI → sources array has 2 entries"
RES=$(curl -s "$BASE/files/$SHA_MULTI")
check "multi get: 2 sources" '(.sources | length) == 2' "$RES" "true"

info "GET /auth?sha256=SHA_MULTI → 403 block"
CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/auth?sha256=$SHA_MULTI")
check "multi auth: HTTP 403" "" "$CODE" "403"
ACTION_HDR=$(curl -s -D - -o /dev/null "$BASE/auth?sha256=$SHA_MULTI" \
    | grep -i '^X-Scan-Action:' | tr -d '\r' | awk '{print $2}')
check "multi auth: X-Scan-Action=block" "" "$ACTION_HDR" "block"

# ============================================================================
sep "Backup endpoint"
# ============================================================================
info "GET /admin/backup — must return 200 and non-empty octet-stream"
HDRS=$(curl -s -D - -o /tmp/openfilerep_test.dump "$BASE/admin/backup")
CODE=$(echo "$HDRS" | grep -i '^HTTP/' | awk '{print $2}')
CTYPE=$(echo "$HDRS" | grep -i '^Content-Type:' | tr -d '\r' | awk '{print $2}')
BYTES=$(wc -c < /tmp/openfilerep_test.dump 2>/dev/null || echo 0)
check "backup: HTTP 200"                   "" "$CODE"  "200"
check "backup: Content-Type octet-stream"  "" "$CTYPE" "application/octet-stream"
check "backup: non-empty dump"             "" "$([ "$BYTES" -gt 0 ] && echo yes || echo no)" "yes"
info "backup size: ${BYTES} bytes"
rm -f /tmp/openfilerep_test.dump

# ============================================================================
sep "Metrics"
# ============================================================================
METRICS=$(curl -s "$BASE/metrics")
BUILD_VER=$(echo "$METRICS" | grep '^open_filerep_build_info' | grep -o 'version="[^"]*"' | cut -d'"' -f2)
check "metrics: build_info present" "$([ -n "$BUILD_VER" ] && echo yes || echo no)" "" "yes"
info "build version: $BUILD_VER"

# ============================================================================
sep "Cleanup"
# ============================================================================
for HASH in "$SHA_CLEAN" "$SHA_EICAR" "$SHA_MULTI" "$SHA_NAMES" "$SHA_WHITELIST"; do
    curl -s -o /dev/null -X DELETE "$BASE/files/$HASH"
done

# ============================================================================
sep "Summary"
# ============================================================================
echo
echo "  PASSED : $PASS"
echo "  FAILED : $FAIL"
echo
[ "$FAIL" -eq 0 ] && echo "  ALL TESTS PASSED" || echo "  SOME TESTS FAILED"
