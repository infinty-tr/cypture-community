package server

import (
	"testing"

	"cypture/internal/models"
)

func TestFindingPath_Normalizes(t *testing.T) {
	cases := map[string]string{
		"https://t.com/search?q=1": "/search",
		"http://t.com/search":      "/search",
		"/search?q=2":              "/search",
		"/search/":                 "/search",
		"/Search":                  "/search",
		"t.com/api/v1/orders#frag": "/api/v1/orders",
		"":                         "",
		"/":                        "/",
	}
	for in, want := range cases {
		if got := findingPath(in); got != want {
			t.Errorf("findingPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSameFinding_CollapsesSameClassSamePath(t *testing.T) {

	a := models.Finding{Title: "SQL Injection in /search", VulnType: "SQLi", Endpoint: "https://t.com/search?q=1"}
	b := models.Finding{Title: "Blind SQL injection - search param", VulnType: "Blind SQL Injection", Endpoint: "/search?q=2"}
	if !sameFinding(a, b) {
		t.Fatal("same class (sqli) + same path (/search) should dedupe despite different titles/endpoints")
	}
}

func TestSameFinding_KeepsDifferentClassesSamePath(t *testing.T) {

	a := models.Finding{Title: "XSS in search", VulnType: "Reflected XSS", Endpoint: "/search"}
	b := models.Finding{Title: "SQLi in search", VulnType: "SQL Injection", Endpoint: "/search"}
	if sameFinding(a, b) {
		t.Fatal("different classes on same path must stay separate")
	}
}

func TestSameFinding_TitleFallbackWhenClassUnknown(t *testing.T) {

	a := models.Finding{Title: "Weird business logic flaw", VulnType: "custom-thing", Endpoint: "/x"}
	b := models.Finding{Title: "WEIRD business logic flaw ", VulnType: "other", Endpoint: "/y"}
	if !sameFinding(a, b) {
		t.Fatal("same normalized title should dedupe when class is unknown")
	}
	c := models.Finding{Title: "A totally different title", VulnType: "custom", Endpoint: "/z"}
	if sameFinding(a, c) {
		t.Fatal("different titles with unknown class must stay separate")
	}
}
