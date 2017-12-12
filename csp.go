package csp

import (
	"fmt"
	"strings"
)

const (
	DispositionEnforce = "enforce"
	DispositionReport  = "report"
)

type Policy struct {
	Disposition string
	Directives  Directives
}

type Directives []Directive

type Directive struct {
	Name  string
	Value []string
}

var (
	ErrDuplicateDirective   = fmt.Errorf("duplicate directive")
	ErrDirectiveNameUnknown = fmt.Errorf("unknown directive name")
)

func ParseDirectives(serializedPolicy string) (Directives, error) {
	d := make(Directives, 0)

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

		// Verify name
		switch strings.ToLower(name) {
		case "child-src":
		case "connect-src":
		case "default-src":
		case "font-src":
		case "frame-src":
		case "img-src":
		case "manifest-src":
		case "media-src":
		case "object-src":
		case "script-src":
		case "style-src":
		case "worker-src":
		case "base-uri":
		case "plugin-types":
		case "sandbox":
		case "disown-opener":
		case "form-action":
		case "frame-ancestors":
		case "report-uri":
		case "report-to":
			// ok

		default:
			return nil, &ParseError{
				Err:    ErrDirectiveNameUnknown,
				Custom: fmt.Sprintf("directive name '%v' is unknown", name),
			}
		}

		// If the set of directives already contains a directive
		// whose name is a case insensitive match for directive name,
		// ignore this instance of the directive and continue to the next token.
		// The user agent SHOULD notify developers that a directive was ignored.
		for _, dx := range d {
			if strings.ToLower(dx.Name) == strings.ToLower(name) {
				return nil, &ParseError{
					Err:    ErrDuplicateDirective,
					Custom: fmt.Sprintf("directive '%v' is a duplicate", name),
				}
			}
		}

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
