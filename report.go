package csp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

type Report struct {
	BlockedUri         string `json:"blocked-uri"`
	DocumentUri        string `json:"document-uri"`
	Disposition        string `json:"disposition"`
	Referrer           string `json:"referrer"`
	StatusCode         int    `json:"status-code"`
	OriginalPolicy     string `json:"original-policy"`
	ViolatedDirective  string `json:"violated-directive"`
	EffectiveDirective string `json:"effective-directive"`
	ScriptSample       string `json:"script-sample"`
	SourceFile         string `json:"source-file"`
	LineNumber         int    `json:"line-number"`
	ColumnNumber       int    `json:"column-number"`
}

type jsonReportWrapper struct {
	Report *Report `json:"csp-report"`
}

var (
	ErrJsonReportMalformed = fmt.Errorf("json report malformed")
)

func ParseReport(body io.Reader) (*Report, error) {
	var j jsonReportWrapper
	d := json.NewDecoder(body)
	if err := d.Decode(&j); err != nil {
		return nil, err
	}

	if j.Report == nil {
		return nil, ErrJsonReportMalformed
	}

	return j.Report, nil
}

func ParseReportBytes(body []byte) (*Report, error) {
	return ParseReport(bytes.NewReader(body))
}

func ParseReportString(body string) (*Report, error) {
	return ParseReport(strings.NewReader(body))
}
