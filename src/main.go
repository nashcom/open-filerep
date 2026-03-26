// open-filerep — REST API for file SHA-256 status tracking backed by Badger.
//
// Generic CRUD endpoints:
//   POST   /files              add or upsert a file record
//   GET    /files              list all records (optional ?status= filter)
//   GET    /files/{sha256}     get one record by hash
//   PUT    /files/{sha256}     update fileName / note only (no business rules)
//   DELETE /files/{sha256}     remove a record
//
// Scan-specific endpoints (enforce antivirus business rules):
//   GET    /scan/{sha256}      check whether a file needs scanning
//                              ?source=<src>  ?pattern=<version>
//                              action: scan | skip | rescan
//   POST   /scan/clean         report a clean result (ignored if already infected)
//   POST   /scan/infected      report an infected result (always wins)
//
// Simple query-string API — no JSON body, results as key=value text:
//   GET    /simple/check       check action  ?sha256=&pattern=&source=
//   GET    /simple/clean       report clean  ?sha256=&pattern=&fileName=&note=&source=
//   GET    /simple/infected    report infect ?sha256=&pattern=&fileName=&threat=&note=&source=
//   GET    /simple/status      one-word status (clean|infected|quarantined|unknown)  ?sha256=
//
// Auth-request endpoint (nginx auth_request compatible):
//   GET    /auth               ?sha256=  → 200 allow / 403 block, metadata in X-Scan-* headers
//
// Admin:
//   DELETE /files              wipe ALL records (use in dev/test only)
//
// Utility:
//   GET    /health             liveness check
//   GET    /metrics            Prometheus-compatible metrics

package main

import (
    "compress/gzip"
    "encoding/json"
    "flag"
    "fmt"
    "io"
    "log"
    "net/http"
    "os"
    "path/filepath"
    "sort"
    "strconv"
    "strings"
    "sync/atomic"
    "time"

    badger "github.com/dgraph-io/badger/v4"
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// gBuildCommit is set at build time via -ldflags "-X main.gBuildCommit=<sha>"
var gBuildCommit = "dev"

const (
    szVersion     = "0.9.7"
    szDBPath      = "./data"
    szListenAddr  = ":8080"
    szPathFiles   = "/files"
    szPathScan    = "/scan"
    szPathSimple  = "/simple"
    szPathAuth    = "/auth"
    szPathHealth  = "/health"
    szPathMetrics = "/metrics"
    szPathAdmin   = "/admin"

    // Scan check actions returned by GET /scan/{sha256} and GET /simple/check
    szActionScan   = "scan"   // not seen before — proceed with scan
    szActionSkip   = "skip"   // already infected, or same pattern already stored
    szActionRescan = "rescan" // was clean but with an older pattern — rescan needed
)

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

// SourceEntry holds one source's report for a given SHA-256.
type SourceEntry struct {
    Source     string `json:"source"`               // clamav | virustotal | admin | threat-feed
    Status     string `json:"status"`               // clean | infected | unknown | error
    Action     string `json:"action"`               // allow | block | whitelist | monitor
    Threat string `json:"threat,omitempty"`
    Pattern    string `json:"pattern,omitempty"`
    ReportedAt int64  `json:"reportedAt"`           // Unix epoch
    Note       string `json:"note,omitempty"`
}

// FileRecord is stored in Badger under the SHA-256 key.
// EffectiveStatus / EffectiveAction / ResolvedBy are computed by resolve()
// and must never be set directly by callers.
type FileRecord struct {
    SHA256     string   `json:"sha256"`
    FileNames  []string `json:"fileNames,omitempty"` // all known names for this hash, deduped

    // Resolved fields — written by resolve(), read by consumers
    EffectiveStatus string `json:"effectiveStatus"` // clean|infected|quarantined|unknown|error
    EffectiveAction string `json:"effectiveAction"` // allow|block|whitelist|monitor
    ResolvedBy      string `json:"resolvedBy"`      // source name that determined outcome

    Sources []SourceEntry `json:"sources"`

    FirstSeen int64  `json:"firstSeen"` // epoch: when first record was created
    LastSeen  int64  `json:"lastSeen"`  // epoch: most recent source update
    Note      string `json:"note,omitempty"`
}

// addRequest is the body accepted by POST /files (direct CRUD add).
type addRequest struct {
    SHA256     string `json:"sha256"`
    FileName   string `json:"fileName,omitempty"`
    Source     string `json:"source"`
    Status     string `json:"status"`
    Action     string `json:"action"`
    Threat string `json:"threat"`
    Pattern    string `json:"pattern"`
    Note       string `json:"note"`
}

// patchRequest is the body accepted by PUT /files/{sha256} (no business rules).
// Only fileName and note are patchable — sources are managed via scan API.
type patchRequest struct {
    Note     string `json:"note"`
    FileName string `json:"fileName"`
}

// ScanRequest is the body for POST /scan/clean and POST /scan/infected.
type ScanRequest struct {
    SHA256     string `json:"sha256"`
    FileName   string `json:"fileName,omitempty"`
    Pattern    string `json:"pattern"`              // ClamAV pattern version
    Threat string `json:"threat,omitempty"` // virus / threat name (infected only)
    Source     string `json:"source,omitempty"`    // reporting source
    Note       string `json:"note,omitempty"`
}

// ScanCheckResponse is returned by GET /scan/{sha256}.
type ScanCheckResponse struct {
    Action string      `json:"action"`            // scan | skip | rescan
    Reason string      `json:"reason"`
    Record *FileRecord `json:"record"`            // nil when action=scan (not seen yet)
}

// ScanResultResponse is returned by POST /scan/clean and POST /scan/infected.
type ScanResultResponse struct {
    Stored bool       `json:"stored"` // false when infected beat an incoming clean
    Reason string     `json:"reason"`
    Record FileRecord `json:"record"`
}

// ---------------------------------------------------------------------------
// Log levels
// ---------------------------------------------------------------------------

const (
    logError = 0 // fatal / unrecoverable errors only
    logInfo  = 1 // startup, wipe, backup — default
    logDebug = 2 // per-request: ADD, UPD, DEL, SCAN, SIMPLE
)

var nLogLevel = logInfo

// logInfo logs at INFO level (startup, significant operations).
func logI(format string, args ...any) {
    if nLogLevel >= logInfo {
        log.Printf(format, args...)
    }
}

// logD logs at DEBUG level (per-request details).
func logD(format string, args ...any) {
    if nLogLevel >= logDebug {
        log.Printf(format, args...)
    }
}

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

var pDB *badger.DB

// tStartTime is used to compute uptime for /metrics.
var tStartTime = time.Now()

// HTTP request counters — updated atomically by each handler.
var (
    qwReqAdd            atomic.Int64
    qwReqList           atomic.Int64
    qwReqGet            atomic.Int64
    qwReqUpdate         atomic.Int64
    qwReqDelete         atomic.Int64
    qwReqScanCheck      atomic.Int64
    qwReqScanClean      atomic.Int64
    qwReqScanInfected   atomic.Int64

    qwReqSimpleCheck    atomic.Int64
    qwReqSimpleClean    atomic.Int64
    qwReqSimpleInfected atomic.Int64
    qwReqSimpleStatus   atomic.Int64
    qwReqAuth           atomic.Int64
    qwReqAdminBackup    atomic.Int64
)

// ---------------------------------------------------------------------------
// Business logic helpers
// ---------------------------------------------------------------------------

// addFileName appends szName to rec.FileNames if it is non-empty and not already present.
func addFileName(rec *FileRecord, szName string) {
    if szName == "" {
        return
    }
    for _, sz := range rec.FileNames {
        if sz == szName {
            return
        }
    }
    rec.FileNames = append(rec.FileNames, szName)
}

// unknownParam returns the first unrecognised query-string key, or "" if all are valid.
// Pass the complete set of accepted parameter names for the endpoint.
func unknownParam(r *http.Request, szAllowed ...string) string {
    mAllowed := make(map[string]struct{}, len(szAllowed))
    for _, sz := range szAllowed {
        mAllowed[sz] = struct{}{}
    }
    for sz := range r.URL.Query() {
        if _, ok := mAllowed[sz]; !ok {
            return sz
        }
    }
    return ""
}

// decodeJSON decodes r.Body into dst, rejecting unknown fields.
func decodeJSON(r *http.Request, dst any) error {
    dec := json.NewDecoder(r.Body)
    dec.DisallowUnknownFields()
    return dec.Decode(dst)
}

// isInfectedStatus returns true for statuses that must not be overwritten by a clean result.
func isInfectedStatus(szStatus string) bool {
    return szStatus == "infected" || szStatus == "quarantined"
}

// isValidSource returns true when szSource is one of the recognised source identifiers.
func isValidSource(szSource string) bool {
    switch szSource {
    case "clamav", "virustotal", "admin", "threat-feed", "manual":
        return true
    }
    return false
}

// resolve computes EffectiveStatus, EffectiveAction, ResolvedBy from rec.Sources.
// Resolution order (first match wins):
//  1. Any source with action == "whitelist"
//  2. Any source with status == "infected" OR action == "block"
//  3. Any source with status == "clean"
//  4. Default → unknown / monitor
func resolve(rec *FileRecord) {
    // Pass 1: whitelist wins — admin trust decision beats all scanner results
    for _, pEntry := range rec.Sources {
        if pEntry.Action == "whitelist" {
            rec.EffectiveStatus = "clean"
            rec.EffectiveAction = "whitelist"
            rec.ResolvedBy = pEntry.Source
            return
        }
    }
    // Pass 2: infected / block wins
    for _, pEntry := range rec.Sources {
        if isInfectedStatus(pEntry.Status) || pEntry.Action == "block" {
            szStatus := pEntry.Status
            if szStatus == "" {
                szStatus = "infected"
            }
            rec.EffectiveStatus = szStatus
            rec.EffectiveAction = "block"
            rec.ResolvedBy = pEntry.Source
            return
        }
    }
    // Pass 3: clean
    for _, pEntry := range rec.Sources {
        if pEntry.Status == "clean" {
            rec.EffectiveStatus = "clean"
            rec.EffectiveAction = "allow"
            rec.ResolvedBy = pEntry.Source
            return
        }
    }
    // Default
    rec.EffectiveStatus = "unknown"
    rec.EffectiveAction = "monitor"
    rec.ResolvedBy = ""
}

// upsertSource updates or appends a SourceEntry in rec, then calls resolve().
func upsertSource(rec *FileRecord, entry SourceEntry) {
    entry.ReportedAt = time.Now().Unix()
    rec.LastSeen = entry.ReportedAt

    // Replace existing entry for this source, or append
    bFound := false
    for i, pExisting := range rec.Sources {
        if pExisting.Source == entry.Source {
            rec.Sources[i] = entry
            bFound = true
            break
        }
    }
    if !bFound {
        rec.Sources = append(rec.Sources, entry)
    }

    resolve(rec)
}

// findSourceEntry returns a pointer to the SourceEntry for szSource, or nil.
func findSourceEntry(rec *FileRecord, szSource string) *SourceEntry {
    for i := range rec.Sources {
        if rec.Sources[i].Source == szSource {
            return &rec.Sources[i]
        }
    }
    return nil
}

// ---------------------------------------------------------------------------
// DB helpers
// ---------------------------------------------------------------------------

func dbPut(szKey string, rec FileRecord) error {
    pbVal, err := json.Marshal(rec)
    if err != nil {
        return err
    }
    return pDB.Update(func(pTxn *badger.Txn) error {
        return pTxn.Set([]byte(szKey), pbVal)
    })
}

func dbGet(szKey string) (FileRecord, error) {
    var rec FileRecord
    err := pDB.View(func(pTxn *badger.Txn) error {
        item, err := pTxn.Get([]byte(szKey))
        if err != nil {
            return err
        }
        return item.Value(func(pbVal []byte) error {
            return json.Unmarshal(pbVal, &rec)
        })
    })
    return rec, err
}

func dbDelete(szKey string) error {
    return pDB.Update(func(pTxn *badger.Txn) error {
        return pTxn.Delete([]byte(szKey))
    })
}

func dbList(szStatusFilter string) ([]FileRecord, error) {
    var vecRecords []FileRecord

    err := pDB.View(func(pTxn *badger.Txn) error {
        opts := badger.DefaultIteratorOptions
        opts.PrefetchSize = 64
        it := pTxn.NewIterator(opts)
        defer it.Close()

        for it.Rewind(); it.Valid(); it.Next() {
            var rec FileRecord
            if err := it.Item().Value(func(pbVal []byte) error {
                return json.Unmarshal(pbVal, &rec)
            }); err != nil {
                return err
            }
            if szStatusFilter == "" || rec.EffectiveStatus == szStatusFilter {
                vecRecords = append(vecRecords, rec)
            }
        }
        return nil
    })

    if vecRecords == nil {
        vecRecords = []FileRecord{} // always return array, never null
    }
    return vecRecords, err
}

// ---------------------------------------------------------------------------
// Backup / restore helpers
// ---------------------------------------------------------------------------

// runBackup opens the database at szDBPath and streams a full backup to szDest.
// szDest may be a file path or "-" for stdout.
// If szDest ends with ".gz" the stream is gzip-compressed automatically.
// Intended for offline / emergency use — will fail if the service is running
// (Badger's file lock prevents two processes opening the same DB).
func runBackup(szDBPath, szDest string) {
    opts := badger.DefaultOptions(szDBPath)
    opts.Logger = nil
    db, err := badger.Open(opts)
    if err != nil {
        log.Fatalf("backup: open db: %v", err)
    }
    defer db.Close()

    var w io.Writer
    if szDest == "-" {
        w = os.Stdout
    } else {
        f, err := os.Create(szDest)
        if err != nil {
            log.Fatalf("backup: create %s: %v", szDest, err)
        }
        defer f.Close()
        if strings.HasSuffix(szDest, ".gz") {
            gz := gzip.NewWriter(f)
            defer gz.Close() // flushes gzip trailer before f.Close()
            w = gz
        } else {
            w = f
        }
    }

    nVersion, err := db.Backup(w, 0)
    if err != nil {
        log.Fatalf("backup: stream: %v", err)
    }
    logI("backup complete  dest=%s  version=%d", szDest, nVersion)
}

// runRestore opens the database at szDBPath, wipes it, and loads a backup from szSrc.
// szSrc may be a file path or "-" for stdin.
// If szSrc ends with ".gz" the stream is decompressed automatically.
// Intended for offline / emergency use — will fail if the service is running.
func runRestore(szDBPath, szSrc string) {
    opts := badger.DefaultOptions(szDBPath)
    opts.Logger = nil
    db, err := badger.Open(opts)
    if err != nil {
        log.Fatalf("restore: open db: %v", err)
    }
    defer db.Close()

    var r io.Reader
    if szSrc == "-" {
        r = os.Stdin
    } else {
        f, err := os.Open(szSrc)
        if err != nil {
            log.Fatalf("restore: open %s: %v", szSrc, err)
        }
        defer f.Close()
        if strings.HasSuffix(szSrc, ".gz") {
            gz, err := gzip.NewReader(f)
            if err != nil {
                log.Fatalf("restore: gzip open %s: %v", szSrc, err)
            }
            defer gz.Close()
            r = gz
        } else {
            r = f
        }
    }

    if err := db.DropAll(); err != nil {
        log.Fatalf("restore: wipe: %v", err)
    }
    if err := db.Load(r, 256); err != nil {
        log.Fatalf("restore: load: %v", err)
    }
    logI("restore complete  src=%s", szSrc)
}

// scheduledBackup writes a timestamped full backup file to szDir using the live pDB,
// then prunes old backup files so at most nKeep files remain (0 = keep all).
// If bGzip is true the file is gzip-compressed and named *.dump.gz.
func scheduledBackup(szDir string, nKeep int, bGzip bool) {
    if err := os.MkdirAll(szDir, 0o755); err != nil {
        logI("BACKUP sched: mkdir %s: %v", szDir, err)
        return
    }

    szExt := ".dump"
    if bGzip {
        szExt = ".dump.gz"
    }
    szName := "open-filerep-" + time.Now().UTC().Format("2006-01-02T15-04-05Z") + szExt
    szPath := filepath.Join(szDir, szName)

    f, err := os.Create(szPath)
    if err != nil {
        logI("BACKUP sched: create %s: %v", szPath, err)
        return
    }

    var w io.Writer = f
    var pGZ *gzip.Writer
    if bGzip {
        pGZ = gzip.NewWriter(f)
        w = pGZ
    }

    nVersion, err := pDB.Backup(w, 0)
    if pGZ != nil {
        pGZ.Close() // flush gzip trailer before closing the file
    }
    f.Close()

    if err != nil {
        logI("BACKUP sched: stream failed: %v", err)
        os.Remove(szPath) // remove partial file
        return
    }
    logI("BACKUP sched: complete  file=%s  version=%d", szPath, nVersion)

    if nKeep > 0 {
        pruneBackups(szDir, nKeep)
    }
}

// pruneBackups deletes the oldest open-filerep-*.dump and *.dump.gz files in szDir,
// keeping only the nKeep most recent across both formats.
func pruneBackups(szDir string, nKeep int) {
    var vecFiles []string
    for _, szPat := range []string{"open-filerep-*.dump", "open-filerep-*.dump.gz"} {
        vecMatches, err := filepath.Glob(filepath.Join(szDir, szPat))
        if err == nil {
            vecFiles = append(vecFiles, vecMatches...)
        }
    }
    if len(vecFiles) <= nKeep {
        return
    }
    sort.Strings(vecFiles) // ISO timestamp prefix sorts lexicographically
    for _, szPath := range vecFiles[:len(vecFiles)-nKeep] {
        if err := os.Remove(szPath); err != nil {
            logI("BACKUP prune: remove %s: %v", szPath, err)
        } else {
            logI("BACKUP prune: removed  %s", szPath)
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, nStatus int, v any) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(nStatus)
    json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, nStatus int, szMsg string) {
    writeJSON(w, nStatus, map[string]string{"error": szMsg})
}

func normHash(szHash string) (string, bool) {
    szHash = strings.ToLower(strings.TrimSpace(szHash))
    return szHash, len(szHash) == 64
}

// nowEpoch returns the current time as Unix epoch seconds.
func nowEpoch() int64 {
    return time.Now().Unix()
}

// epochToStr converts Unix epoch seconds to a human-readable RFC-3339 string.
// Returns empty string for zero value.
func epochToStr(nEpoch int64) string {
    if nEpoch == 0 {
        return ""
    }
    return time.Unix(nEpoch, 0).UTC().Format(time.RFC3339)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

// POST /files
// Body: { "sha256": "...", "fileName": "...", "source": "admin", "status": "clean",
//         "action": "allow", "threat": "", "pattern": "", "note": "" }
func handleAdd(w http.ResponseWriter, r *http.Request) {
    qwReqAdd.Add(1)
    var req addRequest
    if err := decodeJSON(r, &req); err != nil {
        writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
        return
    }

    szHash, bOK := normHash(req.SHA256)
    if !bOK {
        writeError(w, http.StatusBadRequest, "sha256 must be a 64-character hex string")
        return
    }

    // Load or create record
    nNow := nowEpoch()
    rec, errGet := dbGet(szHash)
    if errGet == badger.ErrKeyNotFound {
        rec = FileRecord{
            SHA256:    szHash,
            FirstSeen: nNow,
            Sources:   []SourceEntry{},
        }
    } else if errGet != nil {
        writeError(w, http.StatusInternalServerError, errGet.Error())
        return
    }

    // Build source entry from request
    szSource := req.Source
    if szSource == "" {
        szSource = "admin"
    }
    szStatus := req.Status
    if szStatus == "" {
        szStatus = "unknown"
    }
    szAction := req.Action
    if szAction == "" {
        switch szStatus {
        case "infected", "quarantined":
            szAction = "block"
        case "clean":
            szAction = "allow"
        default:
            szAction = "monitor"
        }
    }

    entry := SourceEntry{
        Source:     szSource,
        Status:     szStatus,
        Action:     szAction,
        Threat: req.Threat,
        Pattern:    req.Pattern,
        Note:       req.Note,
    }
    upsertSource(&rec, entry)

    addFileName(&rec, req.FileName)

    if err := dbPut(szHash, rec); err != nil {
        writeError(w, http.StatusInternalServerError, err.Error())
        return
    }

    logD("ADD  %s  effectiveStatus=%s  effectiveAction=%s  source=%s  files=%v",
        szHash, rec.EffectiveStatus, rec.EffectiveAction, szSource, rec.FileNames)
    writeJSON(w, http.StatusCreated, rec)
}

// GET /files?status=clean
func handleList(w http.ResponseWriter, r *http.Request) {
    qwReqList.Add(1)
    if sz := unknownParam(r, "status"); sz != "" {
        writeError(w, http.StatusBadRequest, "unknown parameter: "+sz)
        return
    }
    szFilter := strings.ToLower(r.URL.Query().Get("status"))

    vecRecords, err := dbList(szFilter)
    if err != nil {
        writeError(w, http.StatusInternalServerError, err.Error())
        return
    }
    writeJSON(w, http.StatusOK, vecRecords)
}

// GET /files/{sha256}
func handleGet(w http.ResponseWriter, r *http.Request, szHash string) {
    qwReqGet.Add(1)
    rec, err := dbGet(szHash)
    if err == badger.ErrKeyNotFound {
        writeError(w, http.StatusNotFound, "not found: "+szHash)
        return
    }
    if err != nil {
        writeError(w, http.StatusInternalServerError, err.Error())
        return
    }
    writeJSON(w, http.StatusOK, rec)
}

// PUT /files/{sha256}
// Body: { "fileName": "...", "note": "..." }
// Only fileName and note may be patched — sources are managed via scan API.
func handleUpdate(w http.ResponseWriter, r *http.Request, szHash string) {
    qwReqUpdate.Add(1)
    rec, err := dbGet(szHash)
    if err == badger.ErrKeyNotFound {
        writeError(w, http.StatusNotFound, "not found: "+szHash)
        return
    }
    if err != nil {
        writeError(w, http.StatusInternalServerError, err.Error())
        return
    }

    var patch patchRequest
    if err := decodeJSON(r, &patch); err != nil {
        writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
        return
    }

    addFileName(&rec, patch.FileName)
    if patch.Note != "" {
        rec.Note = patch.Note
    }
    rec.LastSeen = nowEpoch()

    if err := dbPut(szHash, rec); err != nil {
        writeError(w, http.StatusInternalServerError, err.Error())
        return
    }

    logD("UPD  %s  effectiveStatus=%s", szHash, rec.EffectiveStatus)
    writeJSON(w, http.StatusOK, rec)
}

// DELETE /files/{sha256}
func handleDelete(w http.ResponseWriter, r *http.Request, szHash string) {
    qwReqDelete.Add(1)
    if err := dbDelete(szHash); err == badger.ErrKeyNotFound {
        writeError(w, http.StatusNotFound, "not found: "+szHash)
        return
    } else if err != nil {
        writeError(w, http.StatusInternalServerError, err.Error())
        return
    }

    logD("DEL  %s", szHash)
    w.WriteHeader(http.StatusNoContent)
}

// GET /health
func handleHealth(w http.ResponseWriter, r *http.Request) {
    writeJSON(w, http.StatusOK, map[string]string{
        "status":  "ok",
        "version": szVersion,
        "commit":  gBuildCommit,
    })
}

// GET /metrics — Prometheus text format (no external dependency)
func handleMetrics(w http.ResponseWriter, r *http.Request) {
    // Scan DB to build per-effectiveStatus counts
    dwTotal := 0
    mapStatus := map[string]int{
        "unknown":     0,
        "clean":       0,
        "infected":    0,
        "quarantined": 0,
        "error":       0,
    }

    _ = pDB.View(func(pTxn *badger.Txn) error {
        opts := badger.DefaultIteratorOptions
        opts.PrefetchValues = true
        opts.PrefetchSize  = 64
        it := pTxn.NewIterator(opts)
        defer it.Close()

        for it.Rewind(); it.Valid(); it.Next() {
            var rec FileRecord
            if err := it.Item().Value(func(pbVal []byte) error {
                return json.Unmarshal(pbVal, &rec)
            }); err == nil {
                dwTotal++
                szES := rec.EffectiveStatus
                if szES == "" {
                    szES = "unknown"
                }
                mapStatus[szES]++ // surface it regardless of whether it's a known key
            }
        }
        return nil
    })

    fUptime := time.Since(tStartTime).Seconds()

    w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
    w.WriteHeader(http.StatusOK)

    // ---- build info ----
    fmt.Fprintln(w, "# HELP open_filerep_build_info Version of the running binary")
    fmt.Fprintln(w, "# TYPE open_filerep_build_info gauge")
    fmt.Fprintf (w, "open_filerep_build_info{version=%q,commit=%q} 1\n", szVersion, gBuildCommit)
    fmt.Fprintln(w)

    // ---- uptime ----
    fmt.Fprintln(w, "# HELP open_filerep_uptime_seconds Seconds since the process started")
    fmt.Fprintln(w, "# TYPE open_filerep_uptime_seconds gauge")
    fmt.Fprintf (w, "open_filerep_uptime_seconds %.3f\n", fUptime)
    fmt.Fprintln(w)

    // ---- record counts ----
    fmt.Fprintln(w, "# HELP open_filerep_records_total Total number of file records in the database")
    fmt.Fprintln(w, "# TYPE open_filerep_records_total gauge")
    fmt.Fprintf (w, "open_filerep_records_total %d\n", dwTotal)
    fmt.Fprintln(w)

    fmt.Fprintln(w, "# HELP open_filerep_records_by_status Number of records per effective scan status")
    fmt.Fprintln(w, "# TYPE open_filerep_records_by_status gauge")
    for szStatus, dwCount := range mapStatus {
        fmt.Fprintf(w, "open_filerep_records_by_status{status=%q} %d\n", szStatus, dwCount)
    }
    fmt.Fprintln(w)

    // ---- HTTP request counters ----
    fmt.Fprintln(w, "# HELP open_filerep_http_requests_total HTTP requests handled since start")
    fmt.Fprintln(w, "# TYPE open_filerep_http_requests_total counter")
    fmt.Fprintf (w, "open_filerep_http_requests_total{operation=\"add\"}               %d\n", qwReqAdd.Load())
    fmt.Fprintf (w, "open_filerep_http_requests_total{operation=\"list\"}              %d\n", qwReqList.Load())
    fmt.Fprintf (w, "open_filerep_http_requests_total{operation=\"get\"}               %d\n", qwReqGet.Load())
    fmt.Fprintf (w, "open_filerep_http_requests_total{operation=\"update\"}            %d\n", qwReqUpdate.Load())
    fmt.Fprintf (w, "open_filerep_http_requests_total{operation=\"delete\"}            %d\n", qwReqDelete.Load())
    fmt.Fprintf (w, "open_filerep_http_requests_total{operation=\"scan_check\"}        %d\n", qwReqScanCheck.Load())
    fmt.Fprintf (w, "open_filerep_http_requests_total{operation=\"scan_clean\"}        %d\n", qwReqScanClean.Load())
    fmt.Fprintf (w, "open_filerep_http_requests_total{operation=\"scan_infected\"}     %d\n", qwReqScanInfected.Load())
    fmt.Fprintf (w, "open_filerep_http_requests_total{operation=\"simple_check\"}      %d\n", qwReqSimpleCheck.Load())
    fmt.Fprintf (w, "open_filerep_http_requests_total{operation=\"simple_clean\"}      %d\n", qwReqSimpleClean.Load())
    fmt.Fprintf (w, "open_filerep_http_requests_total{operation=\"simple_infected\"}   %d\n", qwReqSimpleInfected.Load())
    fmt.Fprintf (w, "open_filerep_http_requests_total{operation=\"simple_status\"}     %d\n", qwReqSimpleStatus.Load())
    fmt.Fprintf (w, "open_filerep_http_requests_total{operation=\"auth\"}              %d\n", qwReqAuth.Load())
    fmt.Fprintf (w, "open_filerep_http_requests_total{operation=\"admin_backup\"}      %d\n", qwReqAdminBackup.Load())
}

// ---------------------------------------------------------------------------
// Scan-specific handlers  (/scan/*)
// ---------------------------------------------------------------------------

// GET /scan/{sha256}?source=<src>&pattern={version}
//
// Returns an action telling the caller what to do:
//   scan    — file not seen before, go ahead and scan
//   skip    — already infected/quarantined (no point scanning), or same pattern stored
//   rescan  — stored result is clean but with an older pattern, rescan needed
func handleScanCheck(w http.ResponseWriter, r *http.Request, szHash string) {
    qwReqScanCheck.Add(1)
    if sz := unknownParam(r, "pattern", "source"); sz != "" {
        writeError(w, http.StatusBadRequest, "unknown parameter: "+sz)
        return
    }
    szPattern := r.URL.Query().Get("pattern")
    szSource  := r.URL.Query().Get("source")
    if szSource == "" {
        szSource = "clamav"
    }

    rec, err := dbGet(szHash)
    if err == badger.ErrKeyNotFound {
        writeJSON(w, http.StatusOK, ScanCheckResponse{
            Action: szActionScan,
            Reason: "not seen before",
            Record: nil,
        })
        return
    }
    if err != nil {
        writeError(w, http.StatusInternalServerError, err.Error())
        return
    }

    // Whitelisted by admin — skip, scanner results cannot override this
    if rec.EffectiveAction == "whitelist" {
        writeJSON(w, http.StatusOK, ScanCheckResponse{
            Action: szActionSkip,
            Reason: "whitelisted by admin",
            Record: &rec,
        })
        return
    }

    // If effective status is infected — skip (no scan will change this)
    if isInfectedStatus(rec.EffectiveStatus) {
        writeJSON(w, http.StatusOK, ScanCheckResponse{
            Action: szActionSkip,
            Reason: "already " + rec.EffectiveStatus,
            Record: &rec,
        })
        return
    }

    // Find this source's entry
    pSourceEntry := findSourceEntry(&rec, szSource)
    if pSourceEntry == nil {
        writeJSON(w, http.StatusOK, ScanCheckResponse{
            Action: szActionScan,
            Reason: "source " + szSource + " has not reported yet",
            Record: &rec,
        })
        return
    }

    // Same pattern already stored for this source: skip
    if szPattern != "" && pSourceEntry.Pattern == szPattern {
        writeJSON(w, http.StatusOK, ScanCheckResponse{
            Action: szActionSkip,
            Reason: "already scanned with pattern " + szPattern,
            Record: &rec,
        })
        return
    }

    // Different / missing pattern: rescan
    szReason := "pattern outdated"
    if pSourceEntry.Pattern != "" {
        szReason += " (stored: " + pSourceEntry.Pattern + ", current: " + szPattern + ")"
    }
    writeJSON(w, http.StatusOK, ScanCheckResponse{
        Action: szActionRescan,
        Reason: szReason,
        Record: &rec,
    })
}

// POST /scan/clean
// Body: { "sha256": "...", "fileName": "...", "source": "clamav", "pattern": "...", "note": "..." }
//
// Business rules:
//   - If the effective status is already infected → do NOT overwrite, return stored=false
//   - Otherwise upsert this source's clean entry and re-resolve
func handleScanClean(w http.ResponseWriter, r *http.Request) {
    qwReqScanClean.Add(1)

    var req ScanRequest
    if err := decodeJSON(r, &req); err != nil {
        writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
        return
    }
    szHash, bOK := normHash(req.SHA256)
    if !bOK {
        writeError(w, http.StatusBadRequest, "sha256 must be a 64-character hex string")
        return
    }

    nNow := nowEpoch()
    rec, errGet := dbGet(szHash)
    if errGet == badger.ErrKeyNotFound {
        rec = FileRecord{
            SHA256:    szHash,
            FirstSeen: nNow,
            Sources:   []SourceEntry{},
        }
    } else if errGet != nil {
        writeError(w, http.StatusInternalServerError, errGet.Error())
        return
    }

    // Infected effective status always beats clean from any single source
    if isInfectedStatus(rec.EffectiveStatus) {
        writeJSON(w, http.StatusOK, ScanResultResponse{
            Stored: false,
            Reason: "existing " + rec.EffectiveStatus + " result preserved — infected beats clean",
            Record: rec,
        })
        return
    }

    szSource := req.Source
    if szSource == "" {
        szSource = "clamav"
    }

    entry := SourceEntry{
        Source:  szSource,
        Status:  "clean",
        Action:  "allow",
        Pattern: req.Pattern,
        Note:    req.Note,
    }
    upsertSource(&rec, entry)

    addFileName(&rec, req.FileName)

    if err := dbPut(szHash, rec); err != nil {
        writeError(w, http.StatusInternalServerError, err.Error())
        return
    }

    logD("SCAN clean     %s  pattern=%s  source=%s", szHash, req.Pattern, szSource)
    writeJSON(w, http.StatusOK, ScanResultResponse{
        Stored: true,
        Reason: "clean result recorded",
        Record: rec,
    })
}

// POST /scan/infected
// Body: { "sha256": "...", "fileName": "...", "source": "clamav", "pattern": "...",
//         "threat": "...", "note": "..." }
//
// Business rules:
//   - Infected always wins — always store regardless of previous status
func handleScanInfected(w http.ResponseWriter, r *http.Request) {
    qwReqScanInfected.Add(1)

    var req ScanRequest
    if err := decodeJSON(r, &req); err != nil {
        writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
        return
    }
    szHash, bOK := normHash(req.SHA256)
    if !bOK {
        writeError(w, http.StatusBadRequest, "sha256 must be a 64-character hex string")
        return
    }

    nNow := nowEpoch()
    rec, errGet := dbGet(szHash)
    if errGet == badger.ErrKeyNotFound {
        rec = FileRecord{
            SHA256:    szHash,
            FirstSeen: nNow,
            Sources:   []SourceEntry{},
        }
    } else if errGet != nil {
        writeError(w, http.StatusInternalServerError, errGet.Error())
        return
    }

    szSource := req.Source
    if szSource == "" {
        szSource = "clamav"
    }

    szThreat := req.Threat

    entry := SourceEntry{
        Source:     szSource,
        Status:     "infected",
        Action:     "block",
        Threat: szThreat,
        Pattern:    req.Pattern,
        Note:       req.Note,
    }
    upsertSource(&rec, entry)

    addFileName(&rec, req.FileName)

    if err := dbPut(szHash, rec); err != nil {
        writeError(w, http.StatusInternalServerError, err.Error())
        return
    }

    logD("SCAN infected  %s  pattern=%s  sig=%s  source=%s",
        szHash, req.Pattern, szThreat, szSource)
    writeJSON(w, http.StatusOK, ScanResultResponse{
        Stored: true,
        Reason: "infected result recorded",
        Record: rec,
    })
}

// handleScan dispatches all /scan/* requests.
func handleScan(w http.ResponseWriter, r *http.Request) {
    szSub := strings.TrimPrefix(r.URL.Path, szPathScan+"/")
    szSub  = strings.TrimSpace(szSub)

    switch {
    case r.Method == http.MethodPost && szSub == "clean":
        handleScanClean(w, r)

    case r.Method == http.MethodPost && szSub == "infected":
        handleScanInfected(w, r)

    case r.Method == http.MethodGet:
        szHash, bOK := normHash(szSub)
        if !bOK {
            writeError(w, http.StatusBadRequest, "sha256 must be a 64-character hex string")
            return
        }
        handleScanCheck(w, r, szHash)

    default:
        writeError(w, http.StatusNotFound, "unknown scan endpoint: /scan/"+szSub)
    }
}

// ---------------------------------------------------------------------------
// Simple query-string API  (/simple/*)  and auth endpoint  (/auth)
// ---------------------------------------------------------------------------

// writeText writes a plain-text response body.
func writeText(w http.ResponseWriter, nStatus int, szBody string) {
    w.Header().Set("Content-Type", "text/plain; charset=utf-8")
    w.WriteHeader(nStatus)
    fmt.Fprint(w, szBody)
}

// writeTextKV writes key=value lines from a flat slice: [k0,v0, k1,v1, ...].
func writeTextKV(w http.ResponseWriter, nStatus int, vecPairs ...string) {
    w.Header().Set("Content-Type", "text/plain; charset=utf-8")
    w.WriteHeader(nStatus)
    for i := 0; i+1 < len(vecPairs); i += 2 {
        fmt.Fprintf(w, "%s=%s\n", vecPairs[i], vecPairs[i+1])
    }
}

// recKV converts a FileRecord to a flat key/value slice for writeTextKV.
// Epoch timestamps are rendered as RFC-3339 strings for readability.
// Uses effectiveStatus / effectiveAction for the top-level status / action keys.
// Also emits threat and source from the resolving source entry, if present.
func recKV(rec FileRecord) []string {
    vec := []string{
        "sha256",          rec.SHA256,
        "status",          rec.EffectiveStatus,
        "action",          rec.EffectiveAction,
        "firstSeen",       epochToStr(rec.FirstSeen),
        "lastSeen",        epochToStr(rec.LastSeen),
    }
    for _, szName := range rec.FileNames {
        vec = append(vec, "fileName", szName)
    }
    if rec.ResolvedBy != "" {
        vec = append(vec, "source", rec.ResolvedBy)
    }
    // Surface threat and pattern from the resolving source entry
    if rec.ResolvedBy != "" {
        if pEntry := findSourceEntry(&rec, rec.ResolvedBy); pEntry != nil {
            if pEntry.Threat != "" {
                vec = append(vec, "threat", pEntry.Threat)
            }
            if pEntry.Pattern != "" {
                vec = append(vec, "pattern", pEntry.Pattern)
            }
        }
    }
    if rec.Note != "" {
        vec = append(vec, "note", rec.Note)
    }
    return vec
}

// GET /simple/check?sha256=<hash>&pattern=<version>&source=<src>
// Same logic as GET /scan/{sha256} but returns text/plain key=value lines.
func handleSimpleCheck(w http.ResponseWriter, r *http.Request) {
    qwReqSimpleCheck.Add(1)
    if sz := unknownParam(r, "sha256", "pattern", "source"); sz != "" {
        writeText(w, http.StatusBadRequest, "error=unknown parameter: "+sz+"\n")
        return
    }
    szHash, bOK := normHash(r.URL.Query().Get("sha256"))
    if !bOK {
        writeText(w, http.StatusBadRequest, "error=sha256 must be a 64-character hex string\n")
        return
    }
    szPattern := r.URL.Query().Get("pattern")
    szSource  := r.URL.Query().Get("source")
    if szSource == "" {
        szSource = "clamav"
    } else if !isValidSource(szSource) {
        writeText(w, http.StatusBadRequest,
            "error=unknown source: "+szSource+" (valid: clamav, virustotal, admin, threat-feed, manual)\n")
        return
    }

    rec, err := dbGet(szHash)
    if err == badger.ErrKeyNotFound {
        writeTextKV(w, http.StatusOK,
            "recommend", szActionScan,
            "reason",    "not seen before",
            "sha256",    szHash,
        )
        return
    }
    if err != nil {
        writeText(w, http.StatusInternalServerError, "error="+err.Error()+"\n")
        return
    }

    if isInfectedStatus(rec.EffectiveStatus) {
        vec := []string{"recommend", szActionSkip, "reason", "already " + rec.EffectiveStatus}
        writeTextKV(w, http.StatusOK, append(vec, recKV(rec)...)...)
        return
    }

    pSourceEntry := findSourceEntry(&rec, szSource)
    if pSourceEntry == nil {
        vec := []string{"recommend", szActionScan, "reason", "source " + szSource + " has not reported yet"}
        writeTextKV(w, http.StatusOK, append(vec, recKV(rec)...)...)
        return
    }

    if szPattern != "" && pSourceEntry.Pattern == szPattern {
        vec := []string{"recommend", szActionSkip, "reason", "already scanned with pattern " + szPattern}
        writeTextKV(w, http.StatusOK, append(vec, recKV(rec)...)...)
        return
    }

    szReason := "pattern outdated"
    if pSourceEntry.Pattern != "" {
        szReason += " (stored: " + pSourceEntry.Pattern + ", current: " + szPattern + ")"
    }
    vec := []string{"recommend", szActionRescan, "reason", szReason}
    writeTextKV(w, http.StatusOK, append(vec, recKV(rec)...)...)
}

// GET /simple/clean?sha256=<hash>&pattern=<version>&fileName=<name>&note=<text>&source=<src>
// Same rules as POST /scan/clean — infected beats clean.
func handleSimpleClean(w http.ResponseWriter, r *http.Request) {
    qwReqSimpleClean.Add(1)
    if sz := unknownParam(r, "sha256", "pattern", "source", "fileName", "note"); sz != "" {
        writeText(w, http.StatusBadRequest, "error=unknown parameter: "+sz+"\n")
        return
    }
    szHash, bOK := normHash(r.URL.Query().Get("sha256"))
    if !bOK {
        writeText(w, http.StatusBadRequest, "error=sha256 must be a 64-character hex string\n")
        return
    }

    nNow := nowEpoch()
    rec, errGet := dbGet(szHash)
    if errGet == badger.ErrKeyNotFound {
        rec = FileRecord{
            SHA256:    szHash,
            FirstSeen: nNow,
            Sources:   []SourceEntry{},
        }
    } else if errGet != nil {
        writeText(w, http.StatusInternalServerError, "error="+errGet.Error()+"\n")
        return
    }

    // Infected always beats clean
    if isInfectedStatus(rec.EffectiveStatus) {
        vec := []string{
            "stored", "false",
            "reason", "existing " + rec.EffectiveStatus + " result preserved — infected beats clean",
        }
        writeTextKV(w, http.StatusOK, append(vec, recKV(rec)...)...)
        return
    }

    szSource := r.URL.Query().Get("source")
    if szSource == "" {
        szSource = "clamav"
    } else if !isValidSource(szSource) {
        writeText(w, http.StatusBadRequest,
            "error=unknown source: "+szSource+" (valid: clamav, virustotal, admin, threat-feed, manual)\n")
        return
    }

    entry := SourceEntry{
        Source:  szSource,
        Status:  "clean",
        Action:  "allow",
        Pattern: r.URL.Query().Get("pattern"),
        Note:    r.URL.Query().Get("note"),
    }
    upsertSource(&rec, entry)

    szFileName := r.URL.Query().Get("fileName")
    addFileName(&rec, szFileName)

    if err := dbPut(szHash, rec); err != nil {
        writeText(w, http.StatusInternalServerError, "error="+err.Error()+"\n")
        return
    }

    logD("SIMPLE clean   %s  pattern=%s  source=%s", szHash, entry.Pattern, szSource)
    vec := []string{"stored", "true", "reason", "clean result recorded"}
    writeTextKV(w, http.StatusOK, append(vec, recKV(rec)...)...)
}

// GET /simple/infected?sha256=<hash>&pattern=<version>&fileName=<name>&threat=<name>&note=<text>&source=<src>
// Same rules as POST /scan/infected — always wins.
func handleSimpleInfected(w http.ResponseWriter, r *http.Request) {
    qwReqSimpleInfected.Add(1)
    if sz := unknownParam(r, "sha256", "pattern", "source", "threat", "fileName", "note"); sz != "" {
        writeText(w, http.StatusBadRequest, "error=unknown parameter: "+sz+"\n")
        return
    }
    szHash, bOK := normHash(r.URL.Query().Get("sha256"))
    if !bOK {
        writeText(w, http.StatusBadRequest, "error=sha256 must be a 64-character hex string\n")
        return
    }

    nNow := nowEpoch()
    rec, errGet := dbGet(szHash)
    if errGet == badger.ErrKeyNotFound {
        rec = FileRecord{
            SHA256:    szHash,
            FirstSeen: nNow,
            Sources:   []SourceEntry{},
        }
    } else if errGet != nil {
        writeText(w, http.StatusInternalServerError, "error="+errGet.Error()+"\n")
        return
    }

    szSource := r.URL.Query().Get("source")
    if szSource == "" {
        szSource = "clamav"
    } else if !isValidSource(szSource) {
        writeText(w, http.StatusBadRequest,
            "error=unknown source: "+szSource+" (valid: clamav, virustotal, admin, threat-feed, manual)\n")
        return
    }

    szSig := r.URL.Query().Get("threat")

    entry := SourceEntry{
        Source:     szSource,
        Status:     "infected",
        Action:     "block",
        Threat: szSig,
        Pattern:    r.URL.Query().Get("pattern"),
        Note:       r.URL.Query().Get("note"),
    }
    upsertSource(&rec, entry)

    szFileName := r.URL.Query().Get("fileName")
    addFileName(&rec, szFileName)

    if err := dbPut(szHash, rec); err != nil {
        writeText(w, http.StatusInternalServerError, "error="+err.Error()+"\n")
        return
    }

    logD("SIMPLE infected %s  pattern=%s  sig=%s  source=%s",
        szHash, entry.Pattern, szSig, szSource)
    vec := []string{"stored", "true", "reason", "infected result recorded"}
    writeTextKV(w, http.StatusOK, append(vec, recKV(rec)...)...)
}

// GET /simple/status?sha256=<hash>
// Returns a single word: effectiveStatus (clean | infected | quarantined | error | unknown)
func handleSimpleStatus(w http.ResponseWriter, r *http.Request) {
    qwReqSimpleStatus.Add(1)
    if sz := unknownParam(r, "sha256"); sz != "" {
        writeText(w, http.StatusBadRequest, "error=unknown parameter: "+sz+"\n")
        return
    }

    szHash, bOK := normHash(r.URL.Query().Get("sha256"))
    if !bOK {
        writeText(w, http.StatusBadRequest, "error=sha256 must be a 64-character hex string\n")
        return
    }

    rec, err := dbGet(szHash)
    if err == badger.ErrKeyNotFound {
        writeText(w, http.StatusOK, "unknown\n")
        return
    }
    if err != nil {
        writeText(w, http.StatusInternalServerError, "error="+err.Error()+"\n")
        return
    }
    szStatus := rec.EffectiveStatus
    if szStatus == "" {
        szStatus = "unknown"
    }
    writeText(w, http.StatusOK, szStatus+"\n")
}

// handleSimple dispatches all /simple/* GET requests.
func handleSimple(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        writeText(w, http.StatusMethodNotAllowed, "error=method not allowed\n")
        return
    }
    szSub := strings.TrimPrefix(r.URL.Path, szPathSimple+"/")
    szSub  = strings.TrimSpace(szSub)

    switch szSub {
    case "check":
        handleSimpleCheck(w, r)
    case "clean":
        handleSimpleClean(w, r)
    case "infected":
        handleSimpleInfected(w, r)
    case "status":
        handleSimpleStatus(w, r)
    default:
        writeText(w, http.StatusNotFound, "error=unknown endpoint: /simple/"+szSub+"\n")
    }
}

// GET /auth?sha256=<hash>
//
// Auth-request style endpoint, compatible with nginx auth_request.
// Scan status and metadata are returned as X-Scan-* response headers.
//
// HTTP 200 = allow (clean or unknown — let the mail/proxy pipeline proceed)
// HTTP 403 = block (infected or quarantined)
func handleAuth(w http.ResponseWriter, r *http.Request) {
    qwReqAuth.Add(1)
    if sz := unknownParam(r, "sha256"); sz != "" {
        w.Header().Set("X-Scan-Error", "unknown parameter: "+sz)
        writeText(w, http.StatusBadRequest, "error\n")
        return
    }
    szHash, bOK := normHash(r.URL.Query().Get("sha256"))
    if !bOK {
        w.Header().Set("X-Scan-Error", "sha256 must be a 64-character hex string")
        writeText(w, http.StatusBadRequest, "error\n")
        return
    }

    rec, err := dbGet(szHash)
    if err == badger.ErrKeyNotFound {
        w.Header().Set("X-Scan-Status", "unknown")
        w.Header().Set("X-Scan-SHA256", szHash)
        w.Header().Set("X-Scan-Action", szActionScan)
        writeText(w, http.StatusOK, "unknown\n")
        return
    }
    if err != nil {
        w.Header().Set("X-Scan-Error", err.Error())
        writeText(w, http.StatusInternalServerError, "error\n")
        return
    }

    szEffStatus := rec.EffectiveStatus
    if szEffStatus == "" {
        szEffStatus = "unknown"
    }
    szEffAction := rec.EffectiveAction
    if szEffAction == "" {
        szEffAction = "monitor"
    }

    w.Header().Set("X-Scan-Status",     szEffStatus)
    w.Header().Set("X-Scan-Action",     szEffAction)
    w.Header().Set("X-Scan-SHA256",     rec.SHA256)
    w.Header().Set("X-Scan-ResolvedBy", rec.ResolvedBy)
    w.Header().Set("X-Scan-FirstSeen",  epochToStr(rec.FirstSeen))
    w.Header().Set("X-Scan-LastSeen",   epochToStr(rec.LastSeen))
    if len(rec.FileNames) > 0 {
        w.Header().Set("X-Scan-FileName", strings.Join(rec.FileNames, ", "))
    }
    if rec.Note != "" {
        w.Header().Set("X-Scan-Note", rec.Note)
    }

    // Surface fields from the resolving source entry
    if rec.ResolvedBy != "" {
        if pEntry := findSourceEntry(&rec, rec.ResolvedBy); pEntry != nil {
            if pEntry.Threat != "" {
                w.Header().Set("X-Scan-Threat", pEntry.Threat)
            }
            if pEntry.Source != "" {
                w.Header().Set("X-Scan-Source", pEntry.Source)
            }
            if pEntry.Pattern != "" {
                w.Header().Set("X-Scan-Pattern", pEntry.Pattern)
            }
        }
    }

    if isInfectedStatus(szEffStatus) {
        writeText(w, http.StatusForbidden, szEffStatus+"\n")
        return
    }

    writeText(w, http.StatusOK, szEffStatus+"\n")
}

// ---------------------------------------------------------------------------
// Admin handlers  (/admin/*)
// ---------------------------------------------------------------------------

// GET /admin/backup
//
// Streams a full Badger backup to the caller as application/octet-stream.
// The caller decides what to do with the bytes — write to a file, pipe to
// borg, tar, etc.
//
// Example:
//   curl -s http://localhost:8080/admin/backup > db.dump
//   curl -s http://localhost:8080/admin/backup | borg create --stdin-name db.dump repo::archive -
//
// If the backup stream fails mid-way the connection is closed and the
// partial response should be discarded; the error is logged server-side.
func handleAdminBackup(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        writeError(w, http.StatusMethodNotAllowed, "method not allowed")
        return
    }
    qwReqAdminBackup.Add(1)

    w.Header().Set("Content-Type", "application/octet-stream")
    w.Header().Set("Content-Disposition", `attachment; filename="open-filerep.dump"`)

    nVersion, err := pDB.Backup(w, 0)
    if err != nil {
        // Headers already sent; cannot send a JSON error — just log and drop.
        logI("BACKUP http: stream failed: %v", err)
        return
    }
    logI("BACKUP http: complete  version=%d", nVersion)
}

// handleAdmin dispatches all /admin/* requests.
func handleAdmin(w http.ResponseWriter, r *http.Request) {
    szSub := strings.TrimPrefix(r.URL.Path, szPathAdmin+"/")
    szSub  = strings.TrimSpace(szSub)

    switch szSub {
    case "backup":
        handleAdminBackup(w, r)
    default:
        writeError(w, http.StatusNotFound, "unknown admin endpoint: /admin/"+szSub)
    }
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

// handleFiles routes /files (collection)
// handleWipeAll drops every record from the database.
// Intended for dev/test use only — call DELETE /files with no path segment.
func handleWipeAll(w http.ResponseWriter, r *http.Request) {
    if err := pDB.DropAll(); err != nil {
        writeError(w, http.StatusInternalServerError, "wipe failed: "+err.Error())
        return
    }
    logI("WIPE all records")
    writeJSON(w, http.StatusOK, map[string]string{"wiped": "ok"})
}

func handleFiles(w http.ResponseWriter, r *http.Request) {
    switch r.Method {
    case http.MethodGet:
        handleList(w, r)
    case http.MethodPost:
        handleAdd(w, r)
    case http.MethodDelete:
        handleWipeAll(w, r)
    default:
        writeError(w, http.StatusMethodNotAllowed, "method not allowed")
    }
}

// handleFileByHash routes /files/{sha256} (single record)
func handleFileByHash(w http.ResponseWriter, r *http.Request) {
    szHash := strings.TrimPrefix(r.URL.Path, szPathFiles+"/")
    szHash = strings.TrimSpace(szHash)

    if strings.Contains(szHash, "/") {
        writeError(w, http.StatusBadRequest, "invalid path")
        return
    }

    szHash, bOK := normHash(szHash)
    if !bOK {
        writeError(w, http.StatusBadRequest, "sha256 must be a 64-character hex string")
        return
    }

    switch r.Method {
    case http.MethodGet:
        handleGet(w, r, szHash)
    case http.MethodPut:
        handleUpdate(w, r, szHash)
    case http.MethodDelete:
        handleDelete(w, r, szHash)
    default:
        writeError(w, http.StatusMethodNotAllowed, "method not allowed")
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
    log.SetFlags(log.LstdFlags | log.Lmsgprefix)
    log.SetPrefix("open-filerep: ")

    // ---------------------------------------------------------------------------
    // Helpers: environment variables as fallback for CLI flags.
    // Priority: CLI flag  >  environment variable  >  hardcoded default.
    // All env vars use the FILEREP_ prefix.
    // ---------------------------------------------------------------------------
    envStr := func(szKey, szDefault string) string {
        if sz := os.Getenv(szKey); sz != "" {
            return sz
        }
        return szDefault
    }
    envBool := func(szKey string, bDefault bool) bool {
        switch os.Getenv(szKey) {
        case "true", "1", "yes":
            return true
        case "false", "0", "no":
            return false
        }
        return bDefault
    }
    envDuration := func(szKey string, dDefault time.Duration) time.Duration {
        if sz := os.Getenv(szKey); sz != "" {
            if d, err := time.ParseDuration(sz); err == nil {
                return d
            }
        }
        return dDefault
    }
    envInt := func(szKey string, nDefault int) int {
        if sz := os.Getenv(szKey); sz != "" {
            if n, err := strconv.Atoi(sz); err == nil {
                return n
            }
        }
        return nDefault
    }

    // Command-line flags — env vars provide the default when no flag is passed.
    szDB            := flag.String("db",              envStr("FILEREP_DB",               szDBPath),           "path to Badger database directory  [FILEREP_DB]")
    szAddr          := flag.String("port",            envStr("FILEREP_PORT",             szListenAddr),       "listen address (e.g. :8080)  [FILEREP_PORT]")
    szLogLevel      := flag.String("log-level",       envStr("FILEREP_LOG_LEVEL",        "info"),             "log verbosity: error | info | debug  [FILEREP_LOG_LEVEL]")
    szBackupFile    := flag.String("backup",          "",                                                     "write a full backup to `file` (use - for stdout) then exit; service must not be running")
    szRestoreFile   := flag.String("restore",         "",                                                     "restore from `file` (use - for stdin) then exit; service must not be running")
    szBackupDir     := flag.String("backup-dir",      envStr("FILEREP_BACKUP_DIR",       ""),                 "directory for scheduled local backups (empty = disabled)  [FILEREP_BACKUP_DIR]")
    dBackupInterval := flag.Duration("backup-interval", envDuration("FILEREP_BACKUP_INTERVAL", 24*time.Hour), "interval between scheduled backups (e.g. 6h, 24h)  [FILEREP_BACKUP_INTERVAL]")
    nBackupKeep     := flag.Int("backup-keep",        envInt("FILEREP_BACKUP_KEEP",      7),                  "number of scheduled backup files to keep (0 = keep all)  [FILEREP_BACKUP_KEEP]")
    bBackupGzip     := flag.Bool("backup-gzip",       envBool("FILEREP_BACKUP_GZIP",     false),              "gzip-compress scheduled backup files (saves as .dump.gz)  [FILEREP_BACKUP_GZIP]")
    flag.Parse()

    switch strings.ToLower(*szLogLevel) {
    case "error":
        nLogLevel = logError
    case "info":
        nLogLevel = logInfo
    case "debug":
        nLogLevel = logDebug
    default:
        log.Fatalf("invalid --log-level %q: must be error, info, or debug", *szLogLevel)
    }

    // Emergency offline backup / restore — open the DB directly, then exit.
    // These modes will fail if the service is already running (Badger file lock).
    if *szBackupFile != "" {
        szDest := *szBackupFile
        if *bBackupGzip && szDest != "-" && !strings.HasSuffix(szDest, ".gz") {
            szDest += ".gz"
        }
        runBackup(*szDB, szDest)
        return
    }
    if *szRestoreFile != "" {
        runRestore(*szDB, *szRestoreFile)
        return
    }

    // Open Badger
    opts := badger.DefaultOptions(*szDB)
    opts.Logger = nil // silence Badger's internal logging

    var err error
    pDB, err = badger.Open(opts)
    if err != nil {
        log.Fatalf("open Badger: %v", err)
    }
    defer pDB.Close()

    // Periodic Badger value-log GC (required to reclaim disk space)
    go func() {
        ticker := time.NewTicker(5 * time.Minute)
        defer ticker.Stop()
        for range ticker.C {
            for pDB.RunValueLogGC(0.5) == nil {
            }
        }
    }()

    // Scheduled local backups
    if *szBackupDir != "" {
        go func() {
            ticker := time.NewTicker(*dBackupInterval)
            defer ticker.Stop()
            for range ticker.C {
                scheduledBackup(*szBackupDir, *nBackupKeep, *bBackupGzip)
            }
        }()
        logI("backup    : dir=%s  interval=%s  keep=%d  gzip=%v",
            *szBackupDir, *dBackupInterval, *nBackupKeep, *bBackupGzip)
    }

    // Routes
    mux := http.NewServeMux()
    mux.HandleFunc(szPathFiles,      handleFiles)
    mux.HandleFunc(szPathFiles+"/",  handleFileByHash)
    mux.HandleFunc(szPathScan+"/",   handleScan)
    mux.HandleFunc(szPathSimple+"/", handleSimple)
    mux.HandleFunc(szPathAuth,       handleAuth)
    mux.HandleFunc(szPathHealth,     handleHealth)
    mux.HandleFunc(szPathMetrics,    handleMetrics)
    mux.HandleFunc(szPathAdmin+"/",  handleAdmin)

    logI("version   : %s  commit: %s", szVersion, gBuildCommit)
    logI("database  : %s", *szDB)
    logI("listening : %s", *szAddr)
    logI("log-level : %s", *szLogLevel)

    if err = http.ListenAndServe(*szAddr, mux); err != nil {
        log.Fatalf("listen: %v", err)
    }
}
