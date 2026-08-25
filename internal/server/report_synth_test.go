package server

import "testing"

func TestCleanFindingTitle(t *testing.T) {
	cases := map[string]string{
		"[KRİTİK] Symfony parameters.yml İfşası - Veritabanı": "Symfony parameters.yml İfşası - Veritabanı",
		"[DOĞRULANDI] GoPhish CORS Wildcard: Access-Control":  "GoPhish CORS Wildcard: Access-Control",
		"[HIGH] Symfony Debug Modu production'da açık":        "Symfony Debug Modu production'da açık",
		"[MEDIUM] Nextcloud tju: brute-force koruması devre":  "Nextcloud tju: brute-force koruması devre",
		"[TEORİK] Mass Assignment via Registration Role":      "Mass Assignment via Registration Role",
		"INFO DISCLOSURE - Nextcloud OCS Capabilities API":    "Nextcloud OCS Capabilities API",
		"SECURITY MISCONFIGURATION - Public Link Paylaşımla":  "Public Link Paylaşımla",
		"[LOW][DOĞRULANDI] CORS Misconfiguration":             "CORS Misconfiguration",
		"[GraphQL] Introspection Enabled":                     "[GraphQL] Introspection Enabled",
		"Plain title no tags":                                 "Plain title no tags",
		"[KRİTİK]":                                            "[KRİTİK]",
	}
	for in, want := range cases {
		if got := cleanFindingTitle(in); got != want {
			t.Errorf("cleanFindingTitle(%q)\n  = %q\n want %q", in, got, want)
		}
	}
}

func TestFoldTag(t *testing.T) {
	cases := map[string]string{
		"KRİTİK":     "kritik",
		"Yüksek":     "yuksek",
		"DÜŞÜK":      "dusuk",
		"TEORİK":     "teorik",
		"DOĞRULANDI": "dogrulandi",
		"ZİNCİR":     "zincir",
	}
	for in, want := range cases {
		if got := foldTag(in); got != want {
			t.Errorf("foldTag(%q) = %q, want %q", in, got, want)
		}
	}
}
