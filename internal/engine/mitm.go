package engine

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type certAuthority struct {
	once   sync.Once
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caErr  error
	mu     sync.Mutex
	leaves map[string]*tls.Certificate
}

func (e *Engine) ensureCA() error {
	e.ca.once.Do(func() {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			e.ca.caErr = err
			return
		}
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "Cypture Engine Proxy CA"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().AddDate(2, 0, 0),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			e.ca.caErr = err
			return
		}
		crt, err := x509.ParseCertificate(der)
		if err != nil {
			e.ca.caErr = err
			return
		}
		e.ca.caCert = crt
		e.ca.caKey = key
		e.ca.leaves = map[string]*tls.Certificate{}
	})
	return e.ca.caErr
}

func (e *Engine) ExportCA(path string) error {
	if err := e.ensureCA(); err != nil {
		return err
	}
	if e.ca.caCert == nil {
		return errors.New("could not generate CA")
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.ca.caCert.Raw})
	if dir := filepath.Dir(path); dir != "" {
		_ = os.MkdirAll(dir, 0o755)
	}
	return os.WriteFile(path, pemBytes, 0o644)
}

func (e *Engine) leafFor(host string) (*tls.Certificate, error) {
	e.ca.mu.Lock()
	defer e.ca.mu.Unlock()
	if c, ok := e.ca.leaves[host]; ok {
		return c, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, e.ca.caCert, &key.PublicKey, e.ca.caKey)
	if err != nil {
		return nil, err
	}
	crt := &tls.Certificate{Certificate: [][]byte{der, e.ca.caCert.Raw}, PrivateKey: key}
	e.ca.leaves[host] = crt
	return crt, nil
}

func (e *Engine) mitmServe(client net.Conn, leaf *tls.Certificate, host string, port int) {
	tlsConn := tls.Server(client, &tls.Config{Certificates: []tls.Certificate{*leaf}})
	defer tlsConn.Close()
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	br := bufio.NewReader(tlsConn)
	for {
		_ = tlsConn.SetReadDeadline(time.Now().Add(60 * time.Second))
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}

		if isWebSocketUpgrade(req) {
			e.mitmWebSocket(tlsConn, br, req, host, port)
			return
		}
		if !e.mitmForward(tlsConn, req, host, port) {
			return
		}
	}
}

func isWebSocketUpgrade(req *http.Request) bool {
	return strings.Contains(strings.ToLower(req.Header.Get("Connection")), "upgrade") &&
		strings.EqualFold(strings.TrimSpace(req.Header.Get("Upgrade")), "websocket")
}

func (e *Engine) mitmForward(client net.Conn, req *http.Request, host string, port int) bool {
	body, _ := io.ReadAll(io.LimitReader(req.Body, 10<<20))
	_ = req.Body.Close()

	target := "https://" + host
	if port != 443 {
		target += ":" + strconv.Itoa(port)
	}
	target += req.URL.RequestURI()

	out, err := http.NewRequest(req.Method, target, strings.NewReader(string(body)))
	if err != nil {
		return false
	}
	for k, vs := range req.Header {
		if isHopByHop(k) {
			continue
		}
		for _, v := range vs {
			out.Header.Add(k, v)
		}
	}

	out.Header.Del("Accept-Encoding")

	start := time.Now()
	resp, err := e.defClient.Do(out)
	dur := time.Since(start).Milliseconds()

	entry := &Entry{
		ID: e.nextID("req"), Host: host, Port: port, TLS: true,
		Method: req.Method, Path: req.URL.Path, URL: target,
		DurationMs: dur, At: time.Now(), ReqHeaders: flatten(req.Header),
		ReqBody: clipStr(string(body), e.bodyCap),
	}
	if err != nil {
		entry.Error = err.Error()
		e.store(entry)
		writeRawResponse(client, 502, "text/plain", "proxy upstream error: "+err.Error())
		return false
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	entry.StatusCode = resp.StatusCode
	entry.RespHeader = flatten(resp.Header)

	entry.RespBody = clipStr(string(respBody), e.bodyCap)
	entry.Length = len(respBody)
	if len(respBody) > len(entry.RespBody) {
		entry.TrueLen = len(respBody)
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		entry.RedirectTo = resp.Header.Get("Location")
	}
	e.store(entry)

	resp.Body = io.NopCloser(strings.NewReader(string(respBody)))
	resp.ContentLength = int64(len(respBody))
	resp.Header.Del("Content-Encoding")
	resp.Header.Del("Transfer-Encoding")
	resp.Header.Set("Content-Length", strconv.Itoa(len(respBody)))
	if err := resp.Write(client); err != nil {
		return false
	}
	return !req.Close && req.Header.Get("Connection") != "close"
}

func writeRawResponse(client net.Conn, status int, ctype, body string) {
	resp := &http.Response{
		StatusCode: status, ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{"Content-Type": {ctype}}, Close: true,
		Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)),
	}
	_ = resp.Write(client)
}
