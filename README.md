# go-csp-util

[![Build Status](https://travis-ci.org/templarbit/go-csp-util.svg?branch=master)](https://travis-ci.org/templarbit/go-csp-util)
[![GoDoc](https://godoc.org/github.com/templarbit/go-csp-util?status.svg)](https://godoc.org/github.com/templarbit/go-csp-util)

Content-Security-Policy utils, i.e. CSP parser in compliance with the W3C 
[CSP Level 2](https://www.w3.org/TR/CSP2/) 
and [CSP Level 3](https://www.w3.org/TR/CSP3/) specs.

**ABNF**  
see https://www.w3.org/TR/CSP2/#policy-syntax
and https://www.w3.org/TR/CSP3/#framework

```
serialized-policy    = serialized-directive *( OWS ";" [ OWS serialized-directive ] )
serialized-directive = directive-name [ RWS directive-value ]
directive-name       = 1*( ALPHA / DIGIT / "-" )
directive-value      = *( %x09 / %x20-%x2B / %x2D-%x3A / %x3C-%7E )
                       ; Directive values may contain whitespace and VCHAR characters,
                       ; excluding ";" and ","
```


## Usage

```go
import "github.com/templarbit/go-csp-util"

directives, err := csp.ParseDirectives("default-src 'self'; script-src 'self'; object-src 'self'; base-uri 'none'; report-uri https://ingest.templarbit.com/csp-reports")
```

## Docs

  * Chromium Content Security Policy implementation
    https://cs.chromium.org/chromium/src/content/common/content_security_policy/?type=cs&sq=package:chromium

