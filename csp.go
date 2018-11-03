package csp

import (
	"fmt"
	"strings"
)

const (
	DispositionEnforce = "enforce"
	DispositionReport  = "report"

	ContentSecurityPolicy           = "Content-Security-Policy"
	ContentSecurityPolicyReportOnly = "Content-Security-Policy-Report-Only"
)

type Policy struct {
	Disposition string
	Directives  Directives
}

type Directives []Directive

func (d Directives) String() string {
	o := make([]string, 0)
	for _, v := range d {
		o = append(o, v.String())
	}
	return strings.Join(o, "; ")
}

type Directive struct {
	Name  string
	Value []string
}

func (d Directive) String() string {
	return d.Name + " " + strings.Join(d.Value, " ")
}

var (
	ErrDuplicateDirective      = fmt.Errorf("duplicate directive")
	ErrDirectiveNameUnknown    = fmt.Errorf("unknown directive name")
	ErrDirectiveNameDeprecated = fmt.Errorf("deprecated directive name")
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
		if len(x) == 0 || len(x[0]) == 0 {
			continue
		}
		name := x[0]

		// Verify name
		// see also https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
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
		case "upgrade-insecure-requests":
		case "block-all-mixed-content":
		case "require-sri-for":
			// ok

		case "reflected-xss":
			// ok, deprecated from CSP 2

		case "referrer":
			// ok, deprecated, use Referrer-Policy header

		case "policy-uri":
			return nil, &ParseError{
				Err:    ErrDirectiveNameDeprecated,
				Custom: "policy-uri has been removed and is not supported",
			}

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
			for _, v := range strings.Split(x[1], " ") {
				if len(v) > 0 {
					values = append(values, v)
				}
			}
		}

		// Add directive to directive set.
		d = append(d, Directive{
			Name:  name,
			Value: values,
		})
	}

	return d, nil
}

func (d *Directives) AddDirective(v Directive) error {
	// add values to existing directive if already exists
	added := false
	for i := 0; i < len(*d); i++ {
		if (*d)[i].Name == v.Name {
			(*d)[i].Value = append((*d)[i].Value, v.Value...)
			added = true
			break
		}
	}

	// ... or add new directive
	if !added {
		*d = append(*d, v)
	}

	return nil
}

func (d *Directives) RemoveDirectiveByName(name string) {
	x := make(Directives, 0)
	for _, v := range *d {
		if v.Name != name {
			x = append(x, v)
		}
	}
	*d = x
}
