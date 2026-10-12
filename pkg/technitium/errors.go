package technitium

import (
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrAlreadyExists reports that the zone, app or identical record being
	// created is already present on the server.
	ErrAlreadyExists = errors.New("already exists")

	// ErrSingletonRecordExists reports that a CNAME or DNAME already exists at
	// the name. The server rejects the add without saying whether the existing
	// record is identical, so callers compare it themselves.
	ErrSingletonRecordExists = errors.New("single-value record already exists")

	// ErrNotFound reports that the named zone or app does not exist.
	ErrNotFound = errors.New("not found")

	ErrInvalidToken      = errors.New("invalid or expired token")
	ErrTwoFactorRequired = errors.New("two-factor authentication required")
)

// The server reports these conditions only through errorMessage text. The
// strings are copied from DnsServerCore (WebServiceZonesApi.cs and
// DnsApplicationManager.cs); the e2e rerun assertions fail if they change.
var alreadyExistsMessages = []string{
	"Zone already exists: ",
	"Cannot add record: record already exists.",
	"DNS application already exists: ",
}

const singletonRecordExistsMessage = "Record already exists. Use overwrite option"

var notFoundMessages = []string{
	"DNS application was not found: ",
	"No such zone was found: ",
}

// APIError is a non-ok response from the Technitium HTTP API.
type APIError struct {
	Endpoint   string
	HTTPStatus int
	// Status is the envelope status: "error", "invalid-token" or "2fa-required".
	Status  string
	Message string
}

func (e *APIError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = e.Status
	}
	if e.HTTPStatus != 0 && e.HTTPStatus != 200 {
		return fmt.Sprintf("%s: HTTP %d: %s", e.Endpoint, e.HTTPStatus, msg)
	}
	return fmt.Sprintf("%s: %s", e.Endpoint, msg)
}

func (e *APIError) Is(target error) bool {
	switch target {
	case ErrInvalidToken:
		return e.Status == "invalid-token"
	case ErrTwoFactorRequired:
		return e.Status == "2fa-required"
	case ErrAlreadyExists:
		for _, prefix := range alreadyExistsMessages {
			if strings.HasPrefix(e.Message, prefix) {
				return true
			}
		}
	case ErrSingletonRecordExists:
		return strings.HasPrefix(e.Message, singletonRecordExistsMessage)
	case ErrNotFound:
		for _, prefix := range notFoundMessages {
			if strings.HasPrefix(e.Message, prefix) {
				return true
			}
		}
	}
	return false
}
