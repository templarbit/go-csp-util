package csp

import (
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		in               string
		expectDirectives []Directive
		expectErr        error
	}{
		{
			in: "default-src 'self'; script-src 'self'; object-src 'self'; base-uri 'none'; report-uri https://logs.templarbit.com/csp/foobar/reports;",
			expectDirectives: []Directive{
				{
					Name:  "default-src",
					Value: []string{"'self'"},
				},
				{
					Name:  "script-src",
					Value: []string{"'self'"},
				},
				{
					Name:  "object-src",
					Value: []string{"'self'"},
				},
				{
					Name:  "base-uri",
					Value: []string{"'none'"},
				},
				{
					Name:  "report-uri",
					Value: []string{"https://logs.templarbit.com/csp/foobar/reports"},
				},
			},
			expectErr: nil,
		},
	}

	for i, tt := range tests {
		out, err := Parse(tt.in)
		if err != tt.expectErr {
			t.Fatalf("expect %v, got %v, in %v", tt.expectErr, err, i)
		}

		if len(out) != len(tt.expectDirectives) {
			t.Fatalf("expect len(%v), got len(%v), in %v", len(tt.expectDirectives), len(out), i)
		}

		for j := 0; j < len(out); j++ {
			if out[j].Name != tt.expectDirectives[j].Name {
				t.Errorf("expect %v, got %v, in %v", tt.expectDirectives[j].Name, out[j].Name, i)
			}

			if len(out[j].Value) != len(tt.expectDirectives[j].Value) {
				t.Fatalf("expect len(%v), got len(%v), in %v", len(tt.expectDirectives[j].Value), len(out[j].Value))
			}

			for k := 0; k < len(out[j].Value); k++ {
				if out[j].Value[k] != tt.expectDirectives[j].Value[k] {
					t.Errorf("expect %v, got %v, in %v", tt.expectDirectives[j].Value[k], out[j].Value[k])
				}
			}
		}
	}
}
