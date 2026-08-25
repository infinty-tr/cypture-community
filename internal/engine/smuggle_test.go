package engine

import "testing"

func TestNeedsRawSocket(t *testing.T) {

	clte := "POST / HTTP/1.1\nHost: x\nContent-Length: 6\nTransfer-Encoding: chunked\n\n0\n\nG"
	if !needsRawSocket(clte) {
		t.Fatal("CL.TE request must route to the raw socket path")
	}

	if !needsRawSocket("GET / HTTP/1.1\r\nhost: x\r\ntransfer-encoding: CHUNKED\r\n\r\n") {
		t.Fatal("transfer-encoding detection must be case-insensitive")
	}

	if needsRawSocket("GET /a HTTP/1.1\r\nHost: x\r\n\r\n") {
		t.Fatal("plain request must NOT use the raw socket")
	}

	if needsRawSocket("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 30\r\n\r\nTransfer-Encoding: chunked here") {
		t.Fatal("TE in body must not be treated as a header")
	}
}

func TestParseRawResponse(t *testing.T) {
	status, hdr, body := parseRawResponse("HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Length: 2\r\n\r\nhi")
	if status != 200 {
		t.Fatalf("status = %d, want 200", status)
	}
	if hdr["Server"] != "nginx" {
		t.Fatalf("Server header = %q", hdr["Server"])
	}
	if body != "hi" {
		t.Fatalf("body = %q, want hi", body)
	}

	if _, _, b := parseRawResponse("garbage-no-crlfcrlf"); b != "garbage-no-crlfcrlf" {
		t.Fatalf("partial body = %q", b)
	}
}

func TestRawRequestLine(t *testing.T) {
	m, p := rawRequestLine("POST /login HTTP/1.1\r\nHost: x\r\n\r\n")
	if m != "POST" || p != "/login" {
		t.Fatalf("got %q %q", m, p)
	}
}
