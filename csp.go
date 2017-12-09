package csp

import (
	"strings"
)

const (
	DispositionEnforce = "enforce"
	DispositionReport  = "report"
)

type Policy struct {
	Disposition string
	Directive   []Directive
}

type Directive struct {
	Name  string
	Value []string
}

func Parse(serializedPolicy string) ([]Directive, error) {
	d := make([]Directive, 0)

	// For each token returned by strictly splitting serialized CSP
	// on the U+003B SEMICOLON character (;):
	tokens := strings.Split(serializedPolicy, ";")
	for _, t := range tokens {
		// Strip leading and trailing whitespace from token.
		t = strings.TrimSpace(t)

		// If token is an empty string, skip the remaining substeps
		// and continue to the next item.
		if len(t) == 0 {
			continue
		}

		// Let directive name be the result of collecting
		// a sequence of characters from token which are not space characters.
		x := strings.SplitN(t, " ", 2)

		// The name is a non-empty string
		if len(x) < 0 || len(x[0]) == 0 {
			continue
		}
		name := x[0]

		// The value is a set of non-empty strings. The value set MAY be empty.
		values := make([]string, 0)
		if len(x) > 1 {
			values = strings.Split(x[1], " ")
		}

		// Add directive to directive set.
		d = append(d, Directive{
			Name:  name,
			Value: values,
		})
	}

	return d, nil
}
