package csp

import (
	"testing"
)

func TestParseReport(t *testing.T) {
	report := `{"csp-report": {
		"blocked-uri": "http://evil.com",
		"document-uri": "https://example.com",
		"disposition": "report",
		"referrer": "https://example.com/blog",
		"status-code": 200,
		"original-policy": "default-src 'none'",
		"violated-directive": "default-src 'none'",
		"effective-directive": "default-src 'none'",
		"script-sample": "alert(1)",
		"source-file": "app.js",
		"line-number": 2,
		"column-number": 3
	}}`

	r, err := ParseReportString(report)
	if err != nil {
		t.Fatal(err)
	}

	if r.BlockedUri != "http://evil.com" {
		t.Errorf("blocked-uri")
	}

	if r.DocumentUri != "https://example.com" {
		t.Errorf("document-uri")
	}

	if r.Disposition != "report" {
		t.Errorf("disposition")
	}

	if r.Referrer != "https://example.com/blog" {
		t.Errorf("referrer")
	}

	if r.StatusCode != 200 {
		t.Errorf("status-code")
	}

	if r.OriginalPolicy != "default-src 'none'" {
		t.Errorf("original-policy")
	}

	if r.ViolatedDirective != "default-src 'none'" {
		t.Errorf("violated-directive")
	}

	if r.EffectiveDirective != "default-src 'none'" {
		t.Errorf("effective-directive")
	}

	if r.ScriptSample != "alert(1)" {
		t.Errorf("script-sample")
	}

	if r.SourceFile != "app.js" {
		t.Errorf("source-file")
	}

	if r.LineNumber != 2 {
		t.Errorf("line-number")
	}

	if r.ColumnNumber != 3 {
		t.Errorf("column-number")
	}
}
