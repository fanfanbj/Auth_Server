package authn

import "errors"

// Authentication plugin interface.
type Authenticator interface {
	// Given a user name and a password (plain text), responds with the result or an error.
	// Error should only be reported if request could not be serviced, not if it should be denied.
	// A special NoMatch error is returned if the authorizer could not reach a decision,
	// e.g. none of the rules matched.
	// Implementations must be goroutine-safe.
	Authenticate(user string, password PasswordString) (bool, error)

	// Finalize resources in preparation for shutdown.
	// When this call is made there are guaranteed to be no Authenticate requests in flight
	// and there will be no more calls made to this instance.
	Stop()

	// Human-readable name of the authenticator.
	Name() string
}

var NoMatch = errors.New("did not match any rule")

type PasswordString string

func (ps PasswordString) String() string {
	if len(ps) == 0 {
		return ""
	}
	return "***"
}
