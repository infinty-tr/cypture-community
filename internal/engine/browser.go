package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

type Browser struct {
	eng         *Engine
	allocCancel context.CancelFunc
	cancel      context.CancelFunc
	ctx         context.Context

	mu      sync.Mutex
	dialogs []string
	lastURL string
}

func (e *Engine) getBrowser() (*Browser, error) {
	e.browserMu.Lock()
	defer e.browserMu.Unlock()
	if e.browser != nil {
		return e.browser, nil
	}
	b, err := newBrowser(e)
	if err != nil {
		return nil, err
	}
	e.browser = b
	return b, nil
}

func newBrowser(e *Engine) (*Browser, error) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.NoSandbox,
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("no-first-run", true),
	)
	if p := strings.TrimSpace(os.Getenv("CYP_CHROME_PATH")); p != "" {
		opts = append(opts, chromedp.ExecPath(p))
	}

	bproxy := strings.TrimSpace(os.Getenv("CYP_BROWSER_PROXY"))
	if bproxy == "" {
		bproxy = "127.0.0.1:8080"
	}
	if bproxy != "-" {
		opts = append(opts, chromedp.ProxyServer("http://"+bproxy))
	}
	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	ctx, cancel := chromedp.NewContext(allocCtx)

	b := &Browser{eng: e, allocCancel: allocCancel, cancel: cancel, ctx: ctx}

	chromedp.ListenTarget(ctx, func(ev interface{}) {
		if d, ok := ev.(*page.EventJavascriptDialogOpening); ok {
			b.mu.Lock()
			b.dialogs = append(b.dialogs, d.Type.String()+": "+d.Message)
			b.mu.Unlock()
			go func() { _ = chromedp.Run(ctx, page.HandleJavaScriptDialog(true)) }()
		}
	})

	errc := make(chan error, 1)
	go func() { errc <- chromedp.Run(ctx) }()
	select {
	case err := <-errc:
		if err != nil {
			allocCancel()
			cancel()
			return nil, fmt.Errorf("could not start chromium (a path can be provided via CYP_CHROME_PATH): %w", err)
		}
	case <-time.After(30 * time.Second):
		allocCancel()
		cancel()
		return nil, fmt.Errorf("chromium startup timeout")
	}
	return b, nil
}

func (b *Browser) drainDialogs() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	d := b.dialogs
	b.dialogs = nil
	return d
}

func ensureScheme(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return raw
	}
	if !strings.Contains(raw, "://") {
		return "https://" + raw
	}
	return raw
}

func (b *Browser) Navigate(rawURL string, waitMs, bodyLimit int) (map[string]any, error) {
	target := ensureScheme(rawURL)

	if lo := strings.ToLower(target); !strings.HasPrefix(lo, "http://") && !strings.HasPrefix(lo, "https://") {
		return nil, fmt.Errorf("unsupported scheme (http/https only): %q", rawURL)
	}
	host := normalizeHost(target)
	if host == "" {
		return nil, fmt.Errorf("invalid URL: %q", rawURL)
	}
	if !b.eng.InScope(host) {
		return nil, fmt.Errorf("host %q is out of the authorized scope", host)
	}
	if waitMs <= 0 {
		waitMs = 1500
	}
	if waitMs > 15000 {
		waitMs = 15000
	}
	if bodyLimit <= 0 {
		bodyLimit = 8192
	}
	if bodyLimit > 200000 {
		bodyLimit = 200000
	}
	_ = b.drainDialogs()

	tctx, cancel := context.WithTimeout(b.ctx, 45*time.Second)
	defer cancel()

	var html, title, curURL string
	start := time.Now()
	err := chromedp.Run(tctx,
		chromedp.Navigate(target),
		chromedp.Sleep(time.Duration(waitMs)*time.Millisecond),
		chromedp.Location(&curURL),
		chromedp.Title(&title),
		chromedp.OuterHTML("html", &html, chromedp.ByQuery),
	)
	dur := time.Since(start).Milliseconds()
	dialogs := b.drainDialogs()
	if err != nil {
		return nil, fmt.Errorf("navigate error: %w", err)
	}
	b.lastURL = curURL

	if len(dialogs) > 0 {
		b.eng.recordProof(curURL, "JS dialog triggered in the browser — DOM-XSS verification")
	}

	b.storeNav(curURL, host, title, html)

	return map[string]any{
		"url":         curURL,
		"title":       title,
		"dialogs":     dialogs,
		"html_len":    len(html),
		"html":        clipStr(html, bodyLimit),
		"duration_ms": dur,
	}, nil
}

func (b *Browser) Eval(expr string) (map[string]any, error) {
	if strings.TrimSpace(expr) == "" {
		return nil, fmt.Errorf("expr is required")
	}
	_ = b.drainDialogs()
	tctx, cancel := context.WithTimeout(b.ctx, 20*time.Second)
	defer cancel()
	var res json.RawMessage
	err := chromedp.Run(tctx, chromedp.Evaluate(expr, &res))
	dialogs := b.drainDialogs()

	if len(dialogs) > 0 && b.lastURL != "" {
		b.eng.recordProof(b.lastURL, "JS dialog triggered in browser eval — DOM-XSS verification")
	}
	out := map[string]any{"dialogs": dialogs}
	if err != nil {

		if strings.Contains(strings.ToLower(err.Error()), "undefined") {
			out["result"] = nil
			return out, nil
		}
		return nil, fmt.Errorf("eval error: %w", err)
	}
	out["result"] = json.RawMessage(res)
	return out, nil
}

func (b *Browser) DOM(bodyLimit int) (map[string]any, error) {
	if bodyLimit <= 0 {
		bodyLimit = 16384
	}
	if bodyLimit > 200000 {
		bodyLimit = 200000
	}
	tctx, cancel := context.WithTimeout(b.ctx, 20*time.Second)
	defer cancel()
	var html, curURL string
	if err := chromedp.Run(tctx,
		chromedp.Location(&curURL),
		chromedp.OuterHTML("html", &html, chromedp.ByQuery),
	); err != nil {
		return nil, fmt.Errorf("dom error: %w", err)
	}
	return map[string]any{"url": curURL, "html_len": len(html), "html": clipStr(html, bodyLimit)}, nil
}

func (b *Browser) Screenshot() (map[string]any, error) {
	tctx, cancel := context.WithTimeout(b.ctx, 25*time.Second)
	defer cancel()
	var buf []byte
	if err := chromedp.Run(tctx, chromedp.CaptureScreenshot(&buf)); err != nil {
		return nil, fmt.Errorf("screenshot error: %w", err)
	}
	dir := "/tmp"
	if fp := strings.TrimSpace(os.Getenv("CYP_FEED_PATH")); fp != "" {
		dir = filepath.Join(filepath.Dir(fp), "shots")
	}
	_ = os.MkdirAll(dir, 0o755)
	name := fmt.Sprintf("shot-%d.png", time.Now().UnixNano())
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		return nil, fmt.Errorf("could not write screenshot: %w", err)
	}
	return map[string]any{"path": path, "bytes": len(buf)}, nil
}

func (b *Browser) storeNav(curURL, host, title, html string) {
	path := "/"
	if u, err := url.Parse(curURL); err == nil && u.Path != "" {
		path = u.Path
	}
	en := &Entry{
		ID: b.eng.nextID("req"), Host: host, Method: "GET", Path: path, URL: curURL,
		StatusCode: 200, TLS: strings.HasPrefix(curURL, "https"),
		RespHeader: map[string]string{"X-Cypture-Browser": "rendered (headless chromium)"},
		RespBody:   clipStr(html, b.eng.bodyCap), Length: len(html), At: time.Now(),
	}
	b.eng.store(en)
}

func (b *Browser) Close() {
	if b.cancel != nil {
		b.cancel()
	}
	if b.allocCancel != nil {
		b.allocCancel()
	}
}
