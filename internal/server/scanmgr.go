package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gorm.io/gorm"

	"cypture/internal/config"
	"cypture/internal/kb"
	"cypture/internal/keypool"
	"cypture/internal/models"
	"cypture/internal/orchestrator"
)

type ScanManager struct {
	db     *gorm.DB
	cfg    *config.Config
	hub    *Hub
	runner orchestrator.Runner
	pool   *keypool.Allocator
	kb     *kb.Store

	mu   sync.Mutex
	runs map[string]*scanRun

	reservedTotal int
	reservedUser  map[string]int

	valMu    sync.Mutex
	valCache map[string]llmValidation
}

type llmValidation struct {
	at  time.Time
	msg string
}

const llmValidationTTL = 10 * time.Minute

type scanRun struct {
	scanID       string
	engagementID string
	userID       string
	host         string
	byok         bool
	keyID        string
	cancel       context.CancelFunc

	mu         sync.Mutex
	seq        int
	trafficSeq int64
	pending    *pendingQuestion
	kbUpdate   map[string]any
}

type pendingQuestion struct {
	id       string
	answer   chan string
	defaults string
}

func NewScanManager(db *gorm.DB, cfg *config.Config, hub *Hub) *ScanManager {
	return &ScanManager{
		db:           db,
		cfg:          cfg,
		hub:          hub,
		runner:       orchestrator.NewRunner(cfg.RunnerKind),
		pool:         keypool.New(db),
		kb:           kb.New(db),
		runs:         make(map[string]*scanRun),
		reservedUser: make(map[string]int),
		valCache:     make(map[string]llmValidation),
	}
}

var ErrInsufficientBalance = errors.New("insufficient balance for the selected model")

var ErrTooManyConcurrent = errors.New("too many concurrent scans")

var (
	ErrNoSubscription   = errors.New("no active plan")
	ErrNoScansRemaining = errors.New("no scans remaining")
)

type ErrLLMValidation struct{ Msg string }

func (e *ErrLLMValidation) Error() string { return "llm validation failed: " + e.Msg }

func (m *ScanManager) validateLLM(key, provider, model string) (bool, string) {
	sum := sha256.Sum256([]byte(key + "|" + provider + "|" + model))
	ck := hex.EncodeToString(sum[:])

	m.valMu.Lock()
	if v, ok := m.valCache[ck]; ok && time.Since(v.at) < llmValidationTTL {
		m.valMu.Unlock()
		return true, v.msg
	}
	m.valMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	ok, msg := orchestrator.ValidateLLM(ctx, m.cfg.DockerImage, key, provider, model)
	if ok {
		m.valMu.Lock()
		m.valCache[ck] = llmValidation{at: time.Now(), msg: msg}
		m.valMu.Unlock()
	}
	return ok, msg
}

func (m *ScanManager) Recover() {

	if n := orchestrator.CleanStaleFeedDirs(); n > 0 {
		slog.Warn("crash recovery: removed leaked bridge temp dirs", "dirs", n)
	}
	switch m.cfg.RunnerKind {
	case "k8s", "kubernetes":
		bin := m.cfg.KubectlBin
		if bin == "" {
			bin = "kubectl"
		}

		_ = exec.Command(bin, "--kubeconfig", m.cfg.K8sKubeconfig, "-n", m.cfg.K8sNamespace,
			"delete", "pod", "-l", "app=cypture-engine", "--ignore-not-found", "--wait=true", "--timeout=30s").Run()
	default:
		if out, err := exec.Command("docker", "ps", "-q", "--filter", "name=cyp-").Output(); err == nil {
			for _, id := range strings.Fields(string(out)) {
				_ = exec.Command("docker", "kill", id).Run()
			}
		}
	}

	var orphans []models.ScanSession
	m.db.Where("status IN ?", []models.ScanStatus{
		models.ScanStarting, models.ScanRunning, models.ScanAwaitingInput,
	}).Find(&orphans)
	now := time.Now()
	for _, s := range orphans {
		m.db.Model(&models.ScanSession{}).Where("id = ?", s.ID).
			Updates(map[string]any{"status": models.ScanFailed, "ended_at": &now})
		m.db.Model(&models.Engagement{}).Where("id = ? AND status = ?", s.EngagementID, models.EngRunning).
			Update("status", models.EngFailed)
	}
	if len(orphans) > 0 {
		slog.Warn("crash recovery: marked orphaned scans failed", "scans", len(orphans))
	}
}

func (m *ScanManager) Pool() *keypool.Allocator { return m.pool }

func (m *ScanManager) Start(e *models.Engagement) (string, error) {

	var owner models.User
	m.db.Select("llm_api_key", "llm_provider", "runner_model").First(&owner, "id = ?", e.ClientID)
	byok := strings.TrimSpace(owner.LLMAPIKey) != ""

	llmKey := getSetting(m.db, settingLLMAPIKey)
	if llmKey == "" {
		llmKey = m.cfg.LLMAPIKey
	}
	llmProvider := getSetting(m.db, settingLLMProvider)
	if llmProvider == "" {
		llmProvider = m.cfg.LLMProvider
	}

	model := getSetting(m.db, settingRunnerModel)
	if model == "" {
		model = config.ResolveModel(e.Model, m.cfg.RunnerModel)
	}

	reasoningModel := getSetting(m.db, settingReasoningModel)
	if reasoningModel == "" {
		reasoningModel = m.cfg.ReasoningModel
	}
	if reasoningModel != "" {
		reasoningModel = config.ResolveModel(reasoningModel, reasoningModel)
	}

	if byok {
		llmKey = strings.TrimSpace(owner.LLMAPIKey)
		if p := strings.TrimSpace(owner.LLMProvider); p != "" {
			llmProvider = p
		}
		if rm := strings.TrimSpace(owner.RunnerModel); rm != "" {
			model = rm
		}
	}

	var poolKeyID string
	if !byok {
		if entry, err := m.pool.KeyForUser(e.ClientID); err == nil && entry != nil {
			poolKeyID = entry.ID
			llmKey = strings.TrimSpace(entry.KeyValue)
			if p := strings.TrimSpace(entry.Provider); p != "" {
				llmProvider = p
			}
			if em := strings.TrimSpace(entry.Model); em != "" {
				model = em
			}
		}
	}

	_ = llmKey

	isAdmin := m.userIsAdmin(e.ClientID)
	capsReserved := false
	if m.cfg.MaxConcurrent > 0 || m.cfg.GlobalMaxConcurrent > 0 {
		m.mu.Lock()
		total := len(m.runs) + m.reservedTotal
		userActive := m.reservedUser[e.ClientID]
		for _, r := range m.runs {
			if r.userID == e.ClientID {
				userActive++
			}
		}
		if m.cfg.GlobalMaxConcurrent > 0 && total >= m.cfg.GlobalMaxConcurrent {
			m.mu.Unlock()
			return "", ErrTooManyConcurrent
		}
		if m.cfg.MaxConcurrent > 0 && !isAdmin && userActive >= m.cfg.MaxConcurrent {
			m.mu.Unlock()
			return "", ErrTooManyConcurrent
		}

		m.reservedTotal++
		m.reservedUser[e.ClientID]++
		capsReserved = true
		m.mu.Unlock()
	}

	defer func() {
		if capsReserved {
			m.mu.Lock()
			m.reservedTotal--
			m.reservedUser[e.ClientID]--
			if m.reservedUser[e.ClientID] <= 0 {
				delete(m.reservedUser, e.ClientID)
			}
			m.mu.Unlock()
		}
	}()

	host := normalizeHost(e.Seed)
	workdir := filepath.Join(m.cfg.AgentDir, "targets",
		host+"__"+time.Now().Format("2006-01-02_150405"))
	kbSeed := m.kb.Seed(e.ClientID, host)

	sess := models.ScanSession{
		EngagementID: e.ID,
		Status:       models.ScanStarting,
		WorkDir:      workdir,
		Model:        model,
	}
	if err := m.db.Create(&sess).Error; err != nil {
		return "", err
	}
	m.db.Model(&models.Engagement{}).Where("id = ?", e.ID).Update("status", models.EngRunning)

	ctx, cancel := context.WithCancel(context.Background())
	run := &scanRun{scanID: sess.ID, engagementID: e.ID, userID: e.ClientID, host: host, byok: byok, keyID: poolKeyID, cancel: cancel}

	m.mu.Lock()
	m.runs[sess.ID] = run
	if capsReserved {
		m.reservedTotal--
		m.reservedUser[e.ClientID]--
		if m.reservedUser[e.ClientID] <= 0 {
			delete(m.reservedUser, e.ClientID)
		}
		capsReserved = false
	}
	m.mu.Unlock()

	spec := orchestrator.RunSpec{
		ScanID:          sess.ID,
		Mode:            e.Mode,
		Target:          e.Seed,
		ScopeHosts:      decodeList(e.ScopeIncludes),
		ScopeExcludes:   decodeList(e.ScopeExcludes),
		OperatorPrompt:  e.OperatorPrompt,
		TestCredentials: e.TestCredentials,
		WorkDir:         workdir,
		AgentDir:        m.cfg.AgentDir,
		AgentBin:        m.cfg.AgentBin,
		Model:           model,
		ReasoningModel:  reasoningModel,
		AgentName:       m.cfg.RunnerAgent,
		SkipPerms:       m.cfg.RunnerSkipPerms,
		LLMAPIKey:       llmKey,
		LLMProvider:     llmProvider,
		KBSeed:          kbSeed,

		Image:           m.cfg.DockerImage,
		Network:         m.cfg.DockerNetwork,
		Memory:          m.cfg.DockerMemory,
		CPUs:            m.cfg.DockerCPUs,
		AgentAuthDir:    m.cfg.AgentAuthDir,
		EngineTokenPath: m.cfg.EngineTokenPath,
		BudgetSeconds:   m.cfg.BudgetSeconds,

		Kubeconfig: m.cfg.K8sKubeconfig,
		Namespace:  m.cfg.K8sNamespace,
		KubectlBin: m.cfg.KubectlBin,
	}

	go m.execute(ctx, run, sess.ID, spec)
	return sess.ID, nil
}

func (m *ScanManager) execute(ctx context.Context, run *scanRun, scanID string, spec orchestrator.RunSpec) {

	if spec.BudgetSeconds > 0 {
		var c context.CancelFunc
		ctx, c = context.WithTimeout(ctx, time.Duration(spec.BudgetSeconds)*time.Second)
		defer c()
	}

	now := time.Now()
	m.db.Model(&models.ScanSession{}).Where("id = ?", scanID).
		Updates(map[string]any{"status": models.ScanRunning, "started_at": &now})

	ctrl := &runController{
		mgr: m, run: run, scanID: scanID, ctx: ctx,
		userID: run.userID, model: spec.Model, markup: m.cfg.PriceMarkup,
		meterMsgs: map[string]meterMsg{},
	}
	err := m.runWithFailover(ctx, run, spec, ctrl)

	end := time.Now()
	var scanStatus models.ScanStatus
	var engStatus models.EngagementStatus
	switch {
	case ctx.Err() != nil:
		scanStatus, engStatus = models.ScanStopped, models.EngStopped
		ctrl.Emit(orchestrator.Event{Level: orchestrator.LevelWarning, Category: orchestrator.CatComplete,
			Module: "Çekirdek", Message: "Scan stopped by the operator."})
	case err != nil:
		scanStatus, engStatus = models.ScanFailed, models.EngFailed
		slog.Warn("scan failed", "scan", scanID, "err", err)
		ctrl.Emit(orchestrator.Event{Level: orchestrator.LevelError, Category: orchestrator.CatComplete,
			Module: "Çekirdek", Message: "Scan ended due to an error; you can try again."})
	case !ctrl.sawModel.Load():

		scanStatus, engStatus = models.ScanFailed, models.EngFailed
		slog.Warn("scan produced no model activity (0 tokens) — marking failed", "scan", scanID, "model", spec.Model)
		ctrl.Emit(orchestrator.Event{Level: orchestrator.LevelError, Category: orchestrator.CatComplete,
			Module: "Çekirdek", Message: "The engine could not reach the model — the model may be invalid or the provider unreachable/out of balance. Scan failed. Please check the model in the admin panel."})
	default:
		scanStatus, engStatus = models.ScanCompleted, models.EngCompleted
	}

	m.db.Model(&models.ScanSession{}).Where("id = ?", scanID).
		Updates(map[string]any{"status": scanStatus, "ended_at": &end})
	m.db.Model(&models.Engagement{}).Where("id = ?", run.engagementID).Update("status", engStatus)

	m.collapseScanFindings(scanID)

	m.harvestKB(run)

	m.broadcastLifecycle(scanID, string(scanStatus))

	m.mu.Lock()
	delete(m.runs, scanID)
	m.mu.Unlock()
}

func (m *ScanManager) collapseScanFindings(scanID string) {
	var all []models.Finding
	m.db.Where("scan_session_id = ?", scanID).Order("created_at asc").Find(&all)
	if len(all) < 2 {
		return
	}
	kept := make([]models.Finding, 0, len(all))
	var deleteIDs []string
	for _, f := range all {
		merged := false
		for i := range kept {
			if sameFinding(kept[i], f) {
				if findingStrength(f) > findingStrength(kept[i]) {
					deleteIDs = append(deleteIDs, kept[i].ID)
					kept[i] = f
				} else {
					deleteIDs = append(deleteIDs, f.ID)
				}
				merged = true
				break
			}
		}
		if !merged {
			kept = append(kept, f)
		}
	}
	if len(deleteIDs) > 0 {
		m.db.Where("id IN ?", deleteIDs).Delete(&models.Finding{})
		slog.Info("scan findings collapsed", "scan", scanID, "before", len(all), "after", len(kept), "removed", len(deleteIDs))
	}
}

func (m *ScanManager) runWithFailover(ctx context.Context, run *scanRun, spec orchestrator.RunSpec, ctrl *runController) error {
	if run.byok || run.keyID == "" || m.pool == nil {
		err := m.runner.Run(ctx, spec, ctrl)
		if err == nil && run.keyID != "" {
			m.pool.MarkUsed(run.keyID)
		}
		return err
	}

	tried := map[string]bool{}
	for {
		err := m.runner.Run(ctx, spec, ctrl)
		if err == nil {
			m.pool.MarkUsed(run.keyID)
			return nil
		}
		// Only a key-specific failure (invalid key / no balance) justifies
		// disabling this pool key and rotating. A model-side error (unknown model)
		// is not the key's fault — failing the scan without touching the pool
		// prevents one bad model name from disabling every key in the pool.
		if !errors.Is(err, orchestrator.ErrFatalKey) {
			return err
		}

		tried[run.keyID] = true
		m.pool.Disable(run.keyID, "provider key rejected during scan")
		next, nerr := m.pool.Reassign(run.userID, tried)
		if nerr != nil || next == nil {
			return err
		}
		run.keyID = next.ID
		spec.LLMAPIKey = strings.TrimSpace(next.KeyValue)
		if p := strings.TrimSpace(next.Provider); p != "" {
			spec.LLMProvider = p
		}
		if em := strings.TrimSpace(next.Model); em != "" {
			spec.Model = em
		}
		ctrl.Emit(orchestrator.Event{Level: orchestrator.LevelWarning, Category: orchestrator.CatSystem,
			Module: "Çekirdek", Message: "Provider key changed — restarting the scan with the new key."})
	}
}

func (m *ScanManager) harvestKB(run *scanRun) {
	if run.host == "" {
		return
	}

	var fs []models.Finding
	m.db.Where("scan_session_id = ? AND verified = ?", run.scanID, true).Find(&fs)
	known := make([]kb.KnownFinding, 0, len(fs))
	for _, f := range fs {
		known = append(known, kb.KnownFinding{VulnType: f.VulnType, Endpoint: f.Endpoint, Severity: f.Severity})
	}
	run.mu.Lock()
	upd := run.kbUpdate
	run.mu.Unlock()
	m.kb.Harvest(run.userID, run.host, known, upd)
}

func (m *ScanManager) Stop(scanID string) bool {
	m.mu.Lock()
	run := m.runs[scanID]
	m.mu.Unlock()
	if run == nil {
		return false
	}
	run.cancel()
	return true
}

func (m *ScanManager) Answer(scanID, questionID, optionID string) bool {
	m.mu.Lock()
	run := m.runs[scanID]
	m.mu.Unlock()
	if run == nil {
		return false
	}
	run.mu.Lock()
	pq := run.pending
	run.mu.Unlock()
	if pq == nil || pq.id != questionID {
		return false
	}
	select {
	case pq.answer <- optionID:
		return true
	default:
		return false
	}
}

func (m *ScanManager) broadcastLifecycle(scanID, status string) {
	payload, _ := json.Marshal(map[string]any{
		"type":   "lifecycle",
		"status": status,
	})
	m.hub.Broadcast(scanID, payload)
}

type runController struct {
	mgr    *ScanManager
	run    *scanRun
	scanID string
	ctx    context.Context

	userID string
	model  string
	markup float64

	meterMu   sync.Mutex
	meterMsgs map[string]meterMsg

	findMu sync.Mutex

	sawModel atomic.Bool
}

type meterMsg struct {
	cost, tin, tout, tr int64
}

func (c *runController) nextSeq() int {
	c.run.mu.Lock()
	defer c.run.mu.Unlock()
	c.run.seq++
	return c.run.seq
}

func (c *runController) Emit(ev orchestrator.Event) {

	switch ev.Category {
	case orchestrator.CatFinding, orchestrator.CatTraffic, orchestrator.CatModule, orchestrator.CatPlanning, orchestrator.CatUsage:
		c.sawModel.Store(true)
	}
	switch ev.Level {
	case orchestrator.LevelThought, orchestrator.LevelAction, orchestrator.LevelFinding:
		c.sawModel.Store(true)
	}

	if ev.Category == orchestrator.CatUsage {
		c.meter(ev.Data)
		return
	}

	if ev.Category == orchestrator.CatKB {
		c.run.mu.Lock()
		c.run.kbUpdate = ev.Data
		c.run.mu.Unlock()
		return
	}

	if ev.Category == orchestrator.CatTraffic {
		c.persistTraffic(ev.Data)
		return
	}

	if ev.Category == orchestrator.CatFinding {
		if ev.Data == nil || strings.TrimSpace(dataStr(ev.Data, "title")) == "" {
			return
		}

		if isNegativeResult(ev.Data) {
			return
		}
	}

	ev.Seq = c.nextSeq()

	le := models.LogEvent{
		ScanSessionID: c.scanID,
		Seq:           ev.Seq,
		Level:         ev.Level,
		Category:      ev.Category,
		Module:        ev.Module,
		Message:       ev.Message,
		PaneID:        dataStr(ev.Data, "pane_id"),
		PaneModule:    dataStr(ev.Data, "pane_module"),
		PaneStatus:    dataStr(ev.Data, "pane_status"),
	}
	c.mgr.db.Create(&le)
	c.mgr.db.Model(&models.ScanSession{}).Where("id = ?", c.scanID).Update("last_seq", ev.Seq)

	if ev.Category == orchestrator.CatFinding && ev.Data != nil {
		gateFindingData(ev.Data)
		c.persistFinding(ev.Data)
	}

	payload, _ := json.Marshal(map[string]any{
		"type":     "event",
		"seq":      ev.Seq,
		"level":    ev.Level,
		"category": ev.Category,
		"module":   ev.Module,
		"message":  ev.Message,
		"data":     ev.Data,
	})
	c.mgr.hub.Broadcast(c.scanID, payload)
}

func (c *runController) meter(d map[string]any) {
	if d == nil {
		return
	}
	id := dataStr(d, "msg_id")
	if id == "" {
		id = "_"
	}
	costUSD := dataNum(d, "cost_usd")
	tin := int64(dataNum(d, "tokens_input"))
	tout := int64(dataNum(d, "tokens_output"))
	tr := int64(dataNum(d, "tokens_reasoning"))

	if tin > 0 || tout > 0 || tr > 0 {
		c.sawModel.Store(true)
	}
	model := c.model
	if model == "" {
		model = dataStr(d, "model")
	}

	micros := config.USDToMicros(costUSD)
	if micros == 0 {
		micros = config.PriceTokensMicros(model, tin, tout, tr)
	}
	if c.markup > 0 {
		micros = int64(float64(micros)*c.markup + 0.5)
	}

	c.meterMu.Lock()
	prev := c.meterMsgs[id]
	c.meterMsgs[id] = meterMsg{
		cost: maxI64(micros, prev.cost),
		tin:  maxI64(tin, prev.tin),
		tout: maxI64(tout, prev.tout),
		tr:   maxI64(tr, prev.tr),
	}
	var totCost, totTin, totTout, totTr int64
	for _, mm := range c.meterMsgs {
		totCost += mm.cost
		totTin += mm.tin
		totTout += mm.tout
		totTr += mm.tr
	}
	c.meterMu.Unlock()

	c.mgr.db.Model(&models.ScanSession{}).Where("id = ?", c.scanID).Updates(map[string]any{
		"cost_micros":      totCost,
		"tokens_input":     totTin,
		"tokens_output":    totTout,
		"tokens_reasoning": totTr,
	})

	data := map[string]any{"cost_usd": config.MicrosToUSD(totCost)}
	payload, _ := json.Marshal(map[string]any{"type": "event", "category": "usage", "data": data})
	c.mgr.hub.Broadcast(c.scanID, payload)
}

func maxI64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func dataNum(d map[string]any, k string) float64 {
	switch v := d[k].(type) {
	case float64:
		return v
	case int64:
		return float64(v)
	case int:
		return float64(v)
	}
	return 0
}

func dataStr(d map[string]any, k string) string {
	if s, ok := d[k].(string); ok {
		return s
	}
	return ""
}

func (m *ScanManager) isPaidModel(model string) bool {
	p, ok := config.ModelPrices[model]
	if !ok {
		return true
	}
	return p.InPerM > 0 || p.OutPerM > 0
}

func (m *ScanManager) userIsAdmin(userID string) bool {
	var u models.User
	if err := m.db.Select("role").First(&u, "id = ?", userID).Error; err != nil {
		return false
	}
	return u.Role == models.RoleAdmin
}

func trafficToMap(t models.HTTPTraffic) map[string]any {
	return map[string]any{
		"seq": t.Seq, "method": t.Method, "url": t.URL, "host": t.Host, "path": t.Path,
		"status": t.Status, "duration_ms": t.DurationMs, "length": t.Length, "tls": t.TLS,
		"req_headers": t.ReqHeaders, "req_body": t.ReqBody,
		"resp_headers": t.RespHeaders, "resp_body": t.RespBody,
		"true_len": t.TrueLen, "error": t.Error, "at": t.CreatedAt,
	}
}

func (c *runController) persistTraffic(data map[string]any) {
	if data == nil {
		return
	}
	gs := func(k string) string {
		if s, ok := data[k].(string); ok {
			return s
		}
		return ""
	}
	gi := func(k string) int {
		if f, ok := data[k].(float64); ok {
			return int(f)
		}
		return 0
	}
	hdrJSON := func(k string) string {
		if v, ok := data[k]; ok {
			if b, err := json.Marshal(v); err == nil && string(b) != "null" {
				return string(b)
			}
		}
		return ""
	}
	if gs("method") == "" && gs("url") == "" {
		return
	}
	c.run.mu.Lock()
	c.run.trafficSeq++
	seq := c.run.trafficSeq
	c.run.mu.Unlock()

	tls, _ := data["tls"].(bool)
	t := models.HTTPTraffic{
		ScanSessionID: c.scanID,
		Seq:           seq,
		Method:        gs("method"),
		URL:           orchestrator.Scrub(gs("url")),
		Host:          orchestrator.Scrub(gs("host")),
		Path:          orchestrator.Scrub(gs("path")),
		Status:        gi("status"),
		DurationMs:    int64(gi("duration_ms")),
		Length:        gi("len"),
		TLS:           tls,
		ReqHeaders:    orchestrator.Scrub(hdrJSON("req_headers")),
		ReqBody:       orchestrator.Scrub(gs("req_body")),
		RespHeaders:   orchestrator.Scrub(hdrJSON("resp_headers")),
		RespBody:      orchestrator.Scrub(gs("resp_body")),
		TrueLen:       gi("true_len"),
		Error:         gs("err"),
	}
	c.mgr.db.Create(&t)

	const trafficCap = 3000
	if seq%200 == 0 {
		var ids []string
		c.mgr.db.Model(&models.HTTPTraffic{}).Where("scan_session_id = ?", c.scanID).
			Order("seq DESC").Offset(trafficCap).Pluck("id", &ids)
		if len(ids) > 0 {
			c.mgr.db.Where("id IN ?", ids).Delete(&models.HTTPTraffic{})
		}
	}

	payload, _ := json.Marshal(map[string]any{"type": "traffic", "data": trafficToMap(t)})
	c.mgr.hub.Broadcast(c.scanID, payload)
}

func gateFindingData(data map[string]any) {
	if data == nil {
		return
	}
	gs := func(k string) string { s, _ := data[k].(string); return s }
	proof := strings.TrimSpace(gs("proof_artifact"))
	verified, _ := data["verified"].(bool)
	note := strings.TrimSpace(gs("verify_note"))
	addNote := func(s string) {
		if note == "" {
			note = s
		} else {
			note = s + " " + note
		}
	}

	if verified && proof == "" {
		verified = false
		addNote("[NO ENGINE PROOF — 'verified' badge revoked; it will be raised once the validator proves it]")
	}

	cvss := cvssForFinding(data)

	reqCaptured := strings.TrimSpace(gs("request")) != "" && strings.TrimSpace(gs("response")) != ""
	switch {
	case proof != "":

	case reqCaptured:

		if cvss > 6.9 {
			cvss = 6.9
			addNote("[NOT VERIFIED — a high/critical claim without engine proof was capped at the medium ceiling (6.9); it will be raised once proof arrives]")
		}
	default:

		verified = false
		if cvss > 3.9 {
			cvss = 3.9
			addNote("[NO PROOF — no request+response or proof; lowered to the low ceiling, it will be raised once proof arrives]")
		}
	}
	sev := severityFromCVSS(cvss)
	data["cvss"] = fmt.Sprintf("%.1f", cvss)
	data["severity"] = sev
	if verified {
		data["status"] = "confirmed"
	} else {
		data["status"] = "probable"
	}
	data["verified"] = verified
	data["verify_note"] = note
}

func hasAnySub(hay string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return true
		}
	}
	return false
}

func isNegativeResult(data map[string]any) bool {
	g := func(k string) string { s, _ := data[k].(string); return strings.ToLower(s) }
	hay := g("title") + " " + g("vuln_type") + " " + g("status") + " " + g("verify_note") + " " + g("name") + " " + g("finding_type")
	return hasAnySub(hay,
		"not vulnerable", "not-vulnerable", "not exploitable", "not affected", "not susceptible",
		"no vulnerability", "no vuln found", "not present", "securely configured", "properly configured",
		"correctly configured", "no issue found", "not detected", "no findings", "not found — secure",
		"no vulnerable", "no vulnerable config", "assessment: no", "assessment - no", "- no vulnerab",
		"not applicable", "n/a - ", "disabled (secure)", "(secure)", "- secure", "properly disabled",
		"could not bypass", "couldn't bypass", "no bypass", "bypass edilemedi", "atlatılamad", "atlatilamad",
		"test_note", "test note", "test-note",
		"açık değil", "acik degil", "zafiyet yok", "zafiyet bulunamad", "zafiyet saptanmad", "savunmasız değil",
		"savunmasiz degil", "etkilenmiyor", "güvenli yapılandır", "guvenli yapilandir", "sorun saptanmad")
}

func isNegativeFinding(f models.Finding) bool {
	return isNegativeResult(map[string]any{
		"title": f.Title, "vuln_type": f.VulnType, "status": f.Status,
		"verify_note": f.VerifyNote, "name": f.Title, "finding_type": f.VulnType,
	})
}

func recalibrateRecon(f models.Finding) models.Finding {
	fam := findingFamily(f.Title, f.VulnType)
	sc, ok := reconFamilyCVSS[fam]
	if !ok {
		return f
	}

	if f.Verified {
		return f
	}
	imp := strings.ToLower(f.Title + " " + f.Evidence + " " + f.Impact + " " + f.VulnType + " " + f.ExtractedEvidence)

	if hasAnySub(imp, "source code", "kaynak kod", "credential", "private key", "secret key", "access token",
		"account takeover", "hesap ele geçir", "allow-credentials: true", "allow-credentials:true",
		"student id", "real name", "personal data", "kişisel veri", "kisisel veri", "sensitive data",
		"hassas veri", "arbitrary read", "full read access", "privilege esc", "yetki yükselt") {
		f.CVSS = "5.3"
		f.Severity = severityFromCVSS(5.3)
		return f
	}

	f.CVSS = fmt.Sprintf("%.1f", sc)
	f.Severity = severityFromCVSS(sc)
	return f
}

func isTheoretical(f models.Finding) bool {
	st := strings.ToLower(strings.TrimSpace(f.Status))
	if st == "theoretical" || st == "teorik" || st == "hypothesis" {
		return true
	}
	s := strings.ToLower(f.Title + " " + f.VulnType + " " + f.VerifyNote)
	return hasAnySub(s, "[teorik]", "[theoretical]", "teorik]", "theoretical hypothesis",
		"unconfirmed hypothesis", "hipotez (doğrulanmad", "hipotez (dogrulanmad")
}

var reconFamilyCVSS = map[string]float64{
	"headers":            3.7,
	"cookie-flags":       3.5,
	"clickjacking":       3.5,
	"cors":               3.9,
	"csrf":               3.9,
	"rate-limit":         3.8,
	"info-disclosure":    3.1,
	"version-disclosure": 3.1,
	"source-map":         3.1,
	"debug-disclosure":   3.7,
}

func cvssForFinding(data map[string]any) float64 {
	g := func(k string) string { s, _ := data[k].(string); return strings.ToLower(s) }
	hay := g("type") + " " + g("vuln_type") + " " + g("class") + " " + g("vuln_class") + " " + g("category") +
		" " + g("tag") + " " + g("title") + " " + g("name") + " " + g("finding_type")

	hay = strings.ReplaceAll(hay, "_", " ")

	if hasAnySub(hay, "anomaly", "anomali", "observation", "gözlem", "gozlem", "parser anomaly",
		"behavioral difference", "unexpected response", "unexpected behavior") &&
		!hasAnySub(hay, "inject", "bypass", "traversal", "exfil", "leak", "disclos", "sızınt", "sizint",
			"takeover", "escalat", "unauthor", "yetkisiz", "ssrf", "idor", "xss", "rce", "sqli") {
		return 2.0
	}

	{
		vt, _ := data["vuln_type"].(string)
		ttl, _ := data["title"].(string)
		if sc, ok := reconFamilyCVSS[findingFamily(ttl, vt)]; ok {
			return sc
		}
	}
	switch {

	case hasAnySub(hay, "log4shell", "log4j", "jndi"):
		return 10.0
	case hasAnySub(hay, "rce", "remote code", "command inj", "cmdi", "os command", "code exec", "code injection", "arbitrary code", "eval inj"):
		return 9.8
	case hasAnySub(hay, "deserial", "insecure deser", "object injection", "pickle", "gadget chain"):
		return 9.8
	case hasAnySub(hay, "sql inj", "sqli", "sql injection"):
		return 9.8
	case hasAnySub(hay, "authentication bypass", "auth bypass", "auth-bypass", "login bypass", "kimlik doğrulama atlat"):
		return 9.8
	case hasAnySub(hay, "ssti", "server-side template", "template inj"):
		return 9.6
	case hasAnySub(hay, "arbitrary file upload", "unrestricted file upload", "malicious upload", "webshell", "web shell", "shell upload"):
		return 9.1
	case hasAnySub(hay, "nosql", "nosqli"):
		return 9.1
	case hasAnySub(hay, "xxe", "xml external"):
		return 9.1
	case hasAnySub(hay, "ssrf", "server-side request"):
		return 9.1
	case hasAnySub(hay, "request smuggling", "desync", "http smuggling"):
		return 9.0
	case hasAnySub(hay, "account takeover", "full account", "hesap ele geçir"):
		return 9.0
	case hasAnySub(hay, "ldap inj"):
		return 9.0

	case hasAnySub(hay, "privilege esc", "privesc", "priv-esc", "vertical privilege", "yetki yükselt"):
		return 8.8
	case hasAnySub(hay, "stored xss", "persistent xss", "stored-xss", "stored cross"):
		return 8.8
	case hasAnySub(hay, "xpath inj"):
		return 8.2
	case hasAnySub(hay, "idor", "bola", "insecure direct object", "broken object level", "yetkisiz nesne"):
		return 8.1
	case hasAnySub(hay, "bfla", "broken function level", "broken access", "access control", "authz", "yetkilendirme"):
		return 8.1
	case hasAnySub(hay, "mass assignment", "mass-assign", "autobind", "over-post", "over posting"):
		return 8.1
	case hasAnySub(hay, "prototype pollution", "proto pollution", "__proto__", "sspp"):
		return 8.1
	case hasAnySub(hay, "race condition", "toctou", "race-condition"):
		return 8.1
	case hasAnySub(hay, "type juggling", "type confusion", "type coercion"):
		return 8.1
	case hasAnySub(hay, "cache poison", "web cache", "cache deception"):
		return 8.1
	case hasAnySub(hay, "jwt", "json web token", "jwks", "algorithm confusion"):
		return 8.1
	case hasAnySub(hay, "oauth", "openid", "oidc"):
		return 8.1
	case hasAnySub(hay, "saml"):
		return 8.1
	case hasAnySub(hay, "siwe", "web3", "wallet", "sign-in with ethereum", "sign in with ethereum"):
		return 8.1
	case hasAnySub(hay, "subdomain takeover", "dangling", "sarkık cname", "sarkik cname"):
		return 8.0
	case hasAnySub(hay, "path traversal", "lfi", "local file", "directory traversal", "file inclusion", "rfi", "arbitrary file read", "dizin gezme"):
		return 7.5
	case hasAnySub(hay, "host header"):
		return 7.5
	case hasAnySub(hay, "crlf", "response splitting", "header injection", "header inj"):
		return 7.5
	case hasAnySub(hay, "session fixation", "session hijack", "oturum sabitle"):
		return 7.5

	case hasAnySub(hay, "graphql") && hasAnySub(hay, "inject", "sqli", "authz", "authorization", "access control", "idor", "bola", "yetki"):
		return 7.5
	case hasAnySub(hay, "cswsh", "websocket hijack", "cross-site websocket"):
		return 7.5
	case hasAnySub(hay, "weak crypto", "insecure crypto", "weak cipher", "broken crypto", "padding oracle", "zayıf kripto"):
		return 7.4
	case hasAnySub(hay, "business logic", "iş mantığı", "is mantigi", "workflow bypass", "logic flaw"):
		return 7.3

	case hasAnySub(hay, "mfa", "2fa", "otp bypass", "multi-factor", "two-factor"):
		return 6.5
	case hasAnySub(hay, "csrf", "cross-site request", "cross site request", "sahte istek"):
		return 6.5
	case hasAnySub(hay, "cors"):
		return 6.5
	case hasAnySub(hay, "prompt inj", "llm inj", "jailbreak", "prompt injection"):
		return 6.5
	case hasAnySub(hay, "websocket"):
		return 6.5
	case hasAnySub(hay, "reflected xss", "dom xss", "dom-based", "dom based", "self-xss", "xss", "cross-site script", "cross site script"):
		return 6.1
	case hasAnySub(hay, "open redirect", "open-redirect", "unvalidated redirect", "açık yönlendirme"):
		return 6.1
	case hasAnySub(hay, "postmessage", "post-message"):
		return 6.1
	case hasAnySub(hay, "content spoof", "iframe inj", "text inject", "html inject", "içerik sahte"):
		return 5.3
	case hasAnySub(hay, "brute", "rate limit", "rate-limit", "no rate", "kaba kuvvet"):
		return 5.3

	case hasAnySub(hay, "user enum", "username enum", "account enum", "email enum", "kullanıcı sayım"):
		return 3.5

	case hasAnySub(hay, "verbose error", "stack trace", "trace.axd", "elmah", "debug", "error message", "customerrors", "hata mesaj"):
		return 3.7

	case hasAnySub(hay, "version disclosure", "version_disclosure", "sürüm bilg", "surum bilg", "sürüm ifş", "surum ifs", "sürüm bilgisi", "server header", "banner grab", "x-powered-by", "powered-by", "software version", "technology disclosure", "teknoloji ifş", "fingerprint", "/help page"):
		return 3.1

	case hasAnySub(hay, "credential", "password", "parola", "secret", "api key", "api-key", "apikey", "access token", "auth token", "bearer", "private key", "privatekey", "ssh key", "pii", "personal data", "kişisel veri", "kisisel veri", "credit card", "kredi kart", "session token", "oturum token", ".env", "env file", "source code leak", "kaynak kod sız", "kaynak kod siz", "source code exposure", "kaynak kod erişim", "database dump", "db dump", "sql dump", "backup exposed", "yedek ifş", "internal data", "iç veri"):
		return 5.3

	case hasAnySub(hay, "information disclosure", "info disclosure", "sensitive data", "data exposure", "bilgi sızınt", "bilgi sizint", "leak", "sızınt", "sizint", "exposed", "disclosure", "ifşa"):
		return 3.5

	case hasAnySub(hay, "clickjack", "x-frame", "ui redress", "çerçeveleme"):
		return 4.3
	case hasAnySub(hay, "cookie", "httponly", "samesite", "secure flag"):
		return 4.3
	case hasAnySub(hay, "weak password", "password policy", "zayıf parola"):
		return 4.3
	case hasAnySub(hay, "security header", "missing header", "eksik başlık", "hsts", "csp", "content-security", "x-content-type", "referrer-policy", "permissions-policy"):
		return 3.7

	case hasAnySub(hay, "graphql", "graphiql", "introspection", "apollo sandbox", "__schema"):
		return 3.1
	case hasAnySub(hay, "mixed content", "tls", "ssl", "certificate", "cipher suite", "version disclosure", "fingerprint", "technology", "software version", "banner", "teknoloji", "sürüm", "sertifika"):
		return 3.1
	}

	switch g("severity") {
	case "critical":
		return 9.3
	case "high":
		return 7.8
	case "medium":
		return 5.5
	case "low":
		return 3.5
	}
	return 2.0
}

func severityFromCVSS(c float64) string {
	switch {
	case c >= 9.0:
		return "critical"
	case c >= 7.0:
		return "high"
	case c >= 4.0:
		return "medium"
	case c >= 0.1:
		return "low"
	}
	return "info"
}

func (c *runController) persistFinding(data map[string]any) {
	c.findMu.Lock()
	defer c.findMu.Unlock()
	get := func(k string) string {
		if v, ok := data[k]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
		return ""
	}
	var eng struct{ EngagementID string }
	c.mgr.db.Model(&models.ScanSession{}).Select("engagement_id").Where("id = ?", c.scanID).Scan(&eng)
	getBool := func(k string) bool {
		if v, ok := data[k]; ok {
			if b, ok := v.(bool); ok {
				return b
			}
		}
		return false
	}

	getInt := func(k string) int64 {
		switch v := data[k].(type) {
		case int64:
			return v
		case int:
			return int64(v)
		case float64:
			return int64(v)
		}
		return 0
	}
	f := models.Finding{
		EngagementID:      eng.EngagementID,
		ScanSessionID:     c.scanID,
		Title:             get("title"),
		Severity:          get("severity"),
		VulnType:          get("vuln_type"),
		Endpoint:          get("endpoint"),
		Method:            get("method"),
		Evidence:          get("evidence"),
		Remediation:       get("remediation"),
		PoC:               get("poc"),
		CVSS:              get("cvss"),
		Confidence:        get("confidence"),
		Request:           get("request"),
		Response:          get("response"),
		DurationMs:        getInt("duration_ms"),
		ProofArtifact:     get("proof_artifact"),
		Verified:          getBool("verified"),
		VerifyNote:        get("verify_note"),
		ProofKind:         get("proof_kind"),
		ExtractedEvidence: get("extracted_evidence"),
		ReproSteps:        get("repro_steps"),
		Impact:            get("impact"),
		Status:            get("status"),
	}
	if f.Title == "" {
		return
	}

	var scoped []models.Finding
	c.mgr.db.Where("scan_session_id = ?", c.scanID).Find(&scoped)
	for i := range scoped {
		if sameFinding(scoped[i], f) {

			newWins := findingStrength(f) >= findingStrength(scoped[i])
			upd := f
			if !newWins {
				upd.Severity = scoped[i].Severity
				upd.CVSS = scoped[i].CVSS
				upd.Status = scoped[i].Status
				upd.VerifyNote = scoped[i].VerifyNote
				upd.Verified = scoped[i].Verified
			}
			c.mgr.db.Model(&scoped[i]).Updates(&upd)

			if newWins && strings.TrimSpace(f.VerifyNote) == "" && strings.TrimSpace(scoped[i].VerifyNote) != "" {
				c.mgr.db.Model(&scoped[i]).Update("verify_note", "")
				upd.VerifyNote = ""
			}

			data["severity"] = upd.Severity
			data["cvss"] = upd.CVSS
			data["status"] = upd.Status
			data["verify_note"] = upd.VerifyNote
			data["verified"] = upd.Verified

			data["title"] = scoped[i].Title
			data["vuln_type"] = scoped[i].VulnType
			data["endpoint"] = scoped[i].Endpoint

			data["db_id"] = scoped[i].ID
			return
		}
	}
	c.mgr.db.Create(&f)
	data["db_id"] = f.ID
}

func sameFinding(a, b models.Finding) bool {

	ka, kb := findingDedupKey(a.VulnType, a.Endpoint), findingDedupKey(b.VulnType, b.Endpoint)
	if ka != "" && ka == kb {
		return true
	}
	fa, fb := findingFamily(a.Title, a.VulnType), findingFamily(b.Title, b.VulnType)
	if fa != "" && fb != "" {
		if fa != fb {
			return false
		}

		if siteWideFamily[fa] {
			return true
		}
		return findingPath(a.Endpoint) == findingPath(b.Endpoint)
	}

	return normTitle(a.Title) != "" && normTitle(a.Title) == normTitle(b.Title)
}

var siteWideFamily = map[string]bool{
	"version-disclosure": true,
	"source-map":         true,
	"headers":            true,
	"cors":               true,
	"cookie-flags":       true,
	"clickjacking":       true,
	"rate-limit":         true,
	"csrf":               true,
	"debug-disclosure":   true,
	"proto-pollution":    true,
	"admin-exposure":     true,
}

func findingFamily(title, vulnType string) string {
	ttl := strings.ToLower(title)
	vt := strings.NewReplacer("_", " ", "-", " ").Replace(strings.ToLower(vulnType))

	switch {
	case strings.Contains(ttl, "source map") || strings.Contains(ttl, "sourcemap") ||
		strings.Contains(ttl, ".js.map") || strings.Contains(ttl, ".css.map") ||
		(strings.Contains(ttl, "webpack") && (strings.Contains(ttl, "map") || strings.Contains(ttl, "source") || strings.Contains(ttl, "kaynak"))):
		return "source-map"
	case strings.Contains(ttl, "version disclosure") || strings.Contains(ttl, "version and technology") ||
		strings.Contains(ttl, "version & technology") || strings.Contains(ttl, "technology stack") ||
		strings.Contains(ttl, "server version") || strings.Contains(ttl, "gitlab version") ||
		strings.Contains(ttl, "software version") || strings.Contains(ttl, "version fingerprint") ||
		strings.Contains(ttl, "version banner") || strings.Contains(ttl, "sürüm ifşa"):
		return "version-disclosure"
	}

	if fam := familyMatch(vt); fam != "" {
		return fam
	}

	return familyMatch(ttl + " " + vt)
}

func familyMatch(s string) string {
	has := func(subs ...string) bool {
		for _, x := range subs {
			if strings.Contains(s, x) {
				return true
			}
		}
		return false
	}
	switch {
	case has("sql injection", "sqli", "sql enjeksiyon"):
		return "sqli"
	case has("nosql", "nosqli"):
		return "nosqli"
	case has("cross-site script", "xss"):
		return "xss"
	case has("ssti", "server-side template", "template injection", "template inj"):
		return "ssti"
	case has("xxe", "xml external"):
		return "xxe"
	case has("deserial", "object injection", "gadget chain", "pickle"):
		return "deserialization"
	case has("rce", "remote code", "command inj", "os command", "code injection", "komut enjeksiyon", "kod çalıştır", "kod calistir"):
		return "rce"
	case has("ssrf", "server-side request", "sunucu taraflı istek", "sunucu tarafli istek"):
		return "ssrf"
	case has("idor", "bola", "broken object", "insecure direct object", "yetkisiz nesne"):
		return "idor"
	case has("mass assignment", "mass-assign", "autobind", "over-post", "over posting", "toplu atama"):
		return "mass-assignment"
	case has("prototype pollution", "proto pollution", "__proto__", "sspp"):
		return "proto-pollution"
	case has("path traversal", "lfi", "local file", "/etc/passwd", "directory traversal", "file inclusion", "rfi", "dizin gezme"):
		return "lfi"
	case has("graphql", "graphiql", "introspection"):
		return "graphql"
	case has("jwt", "json web token", "jwks", "algorithm confusion", "alg none", "alg:none"):
		return "jwt"
	case has("oauth", "openid", "oidc", "saml", " sso"):
		return "oauth-saml"
	case has("host header", "host-header"):
		return "host-header"
	case has("crlf", "response splitting", "header injection", "header inj"):
		return "crlf"
	case has("cache poison", "web cache", "cache deception", "önbellek zehir", "onbellek zehir"):
		return "cache-poison"
	case has("race condition", "toctou", "race-condition", "yarış durumu", "yaris durumu"):
		return "race"
	case has("open redirect", "açık yönlendirme", "acik yonlendirme", "unvalidated redirect"):
		return "open-redirect"
	case has("cors"):
		return "cors"
	case has("clickjack", "x-frame", "çerçeveleme", "cerceveleme", "ui redress"):
		return "clickjacking"
	case has("csrf", "cross-site request forgery", "sahte istek"):
		return "csrf"
	case has("admin") && has("panel", "interface", "arayüz", "arayuz", "keşfed", "kesfed", "discover", "exposed", "açığa", "aciga", "erişilebilir", "erisilebilir", "publicly"):
		return "admin-exposure"
	case has("debug"):
		return "debug-disclosure"
	case has("brute", "rate limit", "rate-limit", "kaba kuvvet"):
		return "rate-limit"
	case has("httponly", "secure flag", "samesite", "cookie") && has("flag", "httponly", "secure", "samesite"):
		return "cookie-flags"
	case has("security header", "güvenlik başlık", "guvenlik baslik", "missing header", "eksik başlık", "eksik baslik", "hsts", "content-security-policy", "csp"):
		return "headers"
	case has("information disclosure", "info disclosure", "bilgi sızınt", "bilgi sizint", "teknoloji", "technology", "version", "sürüm", "surum", "leak", "sızınt", "sizint", "fingerprint"):
		return "info-disclosure"
	}
	return ""
}

func stripTagPrefix(s string) string {
	s = strings.TrimSpace(s)
	for strings.HasPrefix(s, "[") {
		i := strings.IndexByte(s, ']')
		if i < 0 {
			break
		}
		s = strings.TrimSpace(s[i+1:])
	}
	return s
}

func normTitle(s string) string { return strings.ToLower(stripTagPrefix(s)) }

func findingDedupKey(vulnType, endpoint string) string {
	cls := kb.CanonClass(vulnType)
	p := findingPath(endpoint)
	if cls == "" || p == "" {
		return ""
	}
	return cls + "|" + p
}

func findingPath(endpoint string) string {
	e := strings.TrimSpace(strings.ToLower(endpoint))
	if e == "" {
		return ""
	}

	for _, m := range []string{"get ", "post ", "put ", "delete ", "patch ", "head ", "options ", "trace ", "connect "} {
		if strings.HasPrefix(e, m) {
			e = strings.TrimSpace(e[len(m):])
			break
		}
	}
	if i := strings.Index(e, "://"); i >= 0 {
		e = e[i+3:]
		if j := strings.IndexByte(e, '/'); j >= 0 {
			e = e[j:]
		} else {
			e = "/"
		}
	} else if !strings.HasPrefix(e, "/") {

		if j := strings.IndexByte(e, '/'); j >= 0 && strings.Contains(e[:j], ".") {
			e = e[j:]
		}
	}
	for _, sep := range []byte{'?', '#'} {
		if i := strings.IndexByte(e, sep); i >= 0 {
			e = e[:i]
		}
	}
	if len(e) > 1 {
		e = strings.TrimRight(e, "/")
	}

	if strings.IndexByte(e, '/') >= 0 {
		segs := strings.Split(e, "/")
		for i, s := range segs {
			if s == "" {
				continue
			}
			if s[0] == '{' || s[0] == ':' || isAllDigits(s) {
				segs[i] = ":id"
			}
		}
		e = strings.Join(segs, "/")
	}
	return e
}

func isAllDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

func (c *runController) Ask(q orchestrator.Question) string {

	optsJSON, _ := json.Marshal(q.Options)
	timeout := q.Timeout
	if timeout <= 0 {
		timeout = 45 * time.Second
	}

	if c.mgr.hub.Subscribers(c.scanID) == 0 {
		if timeout > 20*time.Second {
			timeout = 20 * time.Second
		}
	}
	expires := time.Now().Add(timeout)
	qrow := models.Question{
		ScanSessionID:  c.scanID,
		Prompt:         q.Prompt,
		Options:        string(optsJSON),
		DefaultOption:  q.DefaultID,
		TimeoutSeconds: int(timeout.Seconds()),
		Status:         models.QOpen,
		ExpiresAt:      expires,
	}
	c.mgr.db.Create(&qrow)

	pq := &pendingQuestion{id: qrow.ID, answer: make(chan string, 1), defaults: q.DefaultID}
	c.run.mu.Lock()
	c.run.pending = pq
	c.run.mu.Unlock()

	c.mgr.db.Model(&models.ScanSession{}).Where("id = ?", c.scanID).Update("status", models.ScanAwaitingInput)

	seq := c.nextSeq()
	payload, _ := json.Marshal(map[string]any{
		"type":            "question",
		"seq":             seq,
		"question_id":     qrow.ID,
		"prompt":          q.Prompt,
		"options":         q.Options,
		"default_id":      q.DefaultID,
		"timeout_seconds": int(timeout.Seconds()),
		"expires_at":      expires.Format(time.RFC3339),
	})
	c.mgr.hub.Broadcast(c.scanID, payload)

	c.mgr.db.Create(&models.LogEvent{
		ScanSessionID: c.scanID, Seq: seq, Level: orchestrator.LevelInfo,
		Category: orchestrator.CatQuestion, Module: "Operatör Sorusu", Message: q.Prompt,
	})

	defer func() {
		c.run.mu.Lock()
		c.run.pending = nil
		c.run.mu.Unlock()
		c.mgr.db.Model(&models.ScanSession{}).Where("id = ?", c.scanID).Update("status", models.ScanRunning)
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-c.ctx.Done():
		return ""
	case choice := <-pq.answer:
		c.resolveQuestion(qrow.ID, choice, "user")
		return choice
	case <-timer.C:
		c.resolveQuestion(qrow.ID, q.DefaultID, "auto")
		c.mgr.hub.Broadcast(c.scanID, mustJSON(map[string]any{
			"type": "question_resolved", "question_id": qrow.ID,
			"selected": q.DefaultID, "answered_by": "auto",
		}))
		return q.DefaultID
	}
}

func (c *runController) resolveQuestion(id, selected, by string) {
	now := time.Now()
	status := models.QAnswered
	if by == "auto" {
		status = models.QExpired
	}
	c.mgr.db.Model(&models.Question{}).Where("id = ?", id).Updates(map[string]any{
		"status":          status,
		"selected_option": selected,
		"answered_by":     by,
		"resolved_at":     &now,
	})
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
