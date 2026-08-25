package main

import (
	"os"
	"strconv"
	"strings"

	"cypture/internal/engine"
)

func splitEnv(key string) []string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func intEnv(key string) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return 0
}

func main() {
	eng := engine.New(splitEnv("CYP_SCOPE_INCLUDES"), splitEnv("CYP_SCOPE_EXCLUDES"))

	eng.SetLimits(intEnv("CYP_BODY_CAP"), intEnv("CYP_HISTORY_MAX"), int64(intEnv("CYP_BODY_BUDGET")))

	eng.OpenFeed(os.Getenv("CYP_FEED_PATH"))

	eng.OpenTraffic(os.Getenv("CYP_TRAFFIC_PATH"))

	if oobAddr := strings.TrimSpace(os.Getenv("CYP_OOB_ADDR")); oobAddr != "" {
		o := engine.NewOOB(os.Getenv("CYP_OOB_URL"), os.Getenv("CYP_OOB_DOMAIN"))
		eng.SetOOB(o)
		go func() { _ = o.Start(oobAddr) }()

		if smtpAddr := strings.TrimSpace(os.Getenv("CYP_OOB_SMTP_ADDR")); smtpAddr != "" {
			go func() { _ = o.StartSMTP(smtpAddr) }()
		}
	}

	proxyAddr := os.Getenv("CYP_PROXY_ADDR")
	if proxyAddr == "" {
		proxyAddr = "127.0.0.1:8080"
	}

	if os.Getenv("CYP_PROXY_ONLY") != "" {

		if caPath := strings.TrimSpace(os.Getenv("CYP_CA_EXPORT")); caPath != "" {
			_ = eng.ExportCA(caPath)
		}
		eng.ServeProxy(proxyAddr)
		return
	}

	if proxyAddr != "-" {
		go eng.ServeProxy(proxyAddr)
	}
	srv := engine.NewServer(eng)
	if err := srv.Serve(); err != nil {
		os.Exit(1)
	}
}
