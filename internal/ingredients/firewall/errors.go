//go:build linux

package firewall

import "errors"

var (
	ErrMethodUndefined  = errors.New("firewall method undefined")
	ErrMissingProperty  = errors.New("missing required property")
	ErrInvalidProperty  = errors.New("invalid property value")
	ErrRuleNotFound     = errors.New("named rule not found")
	ErrAmbiguousAddress = errors.New("address family does not match table family")
)
