package csp

import (
	"fmt"
)

type ParseError struct {
	Err    error
	Custom string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("%v: %v", e.Err.Error(), e.Custom)
}
