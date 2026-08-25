package server

import (
	"html/template"
	"os"
	"strings"
)

type Branding struct {
	Product        string
	CompanyName    string
	CompanySite    string
	PartnerName    string
	PartnerSite    string
	Classification string
	Version        string
	LogoDataURI    template.URL
}

func brandEnv(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func defaultBranding() Branding {
	logo := template.URL("")
	if v := strings.TrimSpace(os.Getenv("CYPTURE_REPORT_LOGO_DATA_URI")); v != "" {
		logo = template.URL(v)
	}
	return Branding{
		Product:        brandEnv("CYPTURE_REPORT_PRODUCT", "Cypture"),
		CompanyName:    brandEnv("CYPTURE_REPORT_COMPANY", "Cypture"),
		CompanySite:    brandEnv("CYPTURE_REPORT_SITE", ""),
		PartnerName:    brandEnv("CYPTURE_REPORT_PARTNER", ""),
		PartnerSite:    brandEnv("CYPTURE_REPORT_PARTNER_SITE", ""),
		Classification: brandEnv("CYPTURE_REPORT_CLASSIFICATION", "CONFIDENTIAL"),
		Version:        "1.0",
		LogoDataURI:    logo,
	}
}
