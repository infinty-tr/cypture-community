package engine

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (e *Engine) mitmWebSocket(client net.Conn, clientBR *bufio.Reader, req *http.Request, host string, port int) {

	addr := host + ":" + strconv.Itoa(port)
	up, err := tls.DialWithDialer(&net.Dialer{Timeout: 12 * time.Second}, "tcp", addr,
		&tls.Config{InsecureSkipVerify: true, ServerName: host})
	if err != nil {
		writeRawResponse(client, 502, "text/plain", "ws upstream dial error: "+err.Error())
		return
	}
	defer up.Close()
	_ = up.SetDeadline(time.Now().Add(10 * time.Minute))

	if err := req.Write(up); err != nil {
		return
	}
	upBR := bufio.NewReader(up)
	resp, err := http.ReadResponse(upBR, req)
	if err != nil {
		return
	}

	if err := resp.Write(client); err != nil {
		return
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {

		return
	}

	target := "wss://" + host
	if port != 443 {
		target += ":" + strconv.Itoa(port)
	}
	target += req.URL.RequestURI()

	streamEntry := &Entry{
		ID: e.nextID("ws"), Host: host, Port: port, TLS: true,
		Method: "WS", Path: req.URL.Path, URL: target, StatusCode: 101,
		ReqHeaders: flatten(req.Header), At: time.Now(),
	}
	e.store(streamEntry)
	e.feedWrite(map[string]any{"t": "ws", "dir": "open", "host": host, "path": req.URL.Path, "url": target})

	done := make(chan struct{}, 2)
	go func() { e.pumpWS(clientBR, up, "c2s", host, req.URL.Path); done <- struct{}{} }()
	go func() { e.pumpWS(upBR, client, "s2c", host, req.URL.Path); done <- struct{}{} }()
	<-done
	e.feedWrite(map[string]any{"t": "ws", "dir": "close", "host": host, "path": req.URL.Path})
}

func (e *Engine) pumpWS(src *bufio.Reader, dst io.Writer, dir, host, path string) {
	for {
		raw, opcode, payload, err := readWSFrame(src)
		if err != nil {
			return
		}
		if _, err := dst.Write(raw); err != nil {
			return
		}
		switch opcode {
		case 0x1, 0x2:
			kind := "text"
			if opcode == 0x2 {
				kind = "binary"
			}
			e.feedWrite(map[string]any{
				"t": "ws", "dir": dir, "host": host, "path": path,
				"kind": kind, "len": len(payload), "data": clipStr(strings.ToValidUTF8(string(payload), ""), 1024),
			})
		case 0x8:
			return
		}
	}
}

func readWSFrame(r *bufio.Reader) (raw []byte, opcode byte, payload []byte, err error) {
	h0, err := r.ReadByte()
	if err != nil {
		return nil, 0, nil, err
	}
	h1, err := r.ReadByte()
	if err != nil {
		return nil, 0, nil, err
	}
	opcode = h0 & 0x0F
	masked := h1&0x80 != 0
	var n uint64 = uint64(h1 & 0x7F)

	raw = []byte{h0, h1}
	switch n {
	case 126:
		ext := make([]byte, 2)
		if _, err = io.ReadFull(r, ext); err != nil {
			return nil, 0, nil, err
		}
		raw = append(raw, ext...)
		n = uint64(binary.BigEndian.Uint16(ext))
	case 127:
		ext := make([]byte, 8)
		if _, err = io.ReadFull(r, ext); err != nil {
			return nil, 0, nil, err
		}
		raw = append(raw, ext...)
		n = binary.BigEndian.Uint64(ext)
	}

	if n > 1<<20 {
		return nil, 0, nil, io.ErrShortBuffer
	}
	var mask []byte
	if masked {
		mask = make([]byte, 4)
		if _, err = io.ReadFull(r, mask); err != nil {
			return nil, 0, nil, err
		}
		raw = append(raw, mask...)
	}
	payload = make([]byte, n)
	if _, err = io.ReadFull(r, payload); err != nil {
		return nil, 0, nil, err
	}
	raw = append(raw, payload...)
	if masked {
		unmasked := make([]byte, n)
		for i := range payload {
			unmasked[i] = payload[i] ^ mask[i%4]
		}
		payload = unmasked
	}
	return raw, opcode, payload, nil
}
