package appkeystore

import (
	"fmt"
)

// AppExists is an error indicating an application with a
// given ID already exists.  It may be converted to uin64 to
// retreive the application ID.
type AppExists uint64

func (e AppExists) Error() string {
	return fmt.Sprintf("app %d already exists", uint64(e))
}

// UnallowedAppId is an error indicating that a given app ID may
// not be used.  It may be converted to uint64 to get the
// application ID.
type UnallowedAppId uint64

func (e UnallowedAppId) Error() string {
	return fmt.Sprintf("app id %d is not allowed", uint64(e))
}

// UnsupportedSignatureAlgo is an error indicating that a specified
// signature algorithm is not supported.  It may be converted to
// string to get the identifier of the unsupported algorithm.
type UnsupportedSignatureAlgo string

func (e UnsupportedSignatureAlgo) Error() string {
	return fmt.Sprintf("unsupported algorithm %s", string(e))
}

// NoKeyForApp is an error indicating that a certain application
// has no available key.  It may be converted to uint64 to get
// the application ID.
type NoKeyForApp uint64

func (e NoKeyForApp) Error() string {
	return fmt.Sprintf("No key for app %d", uint64(e))
}

// InvalidClaims is in error indicating that given claims are not
// acceptable.
type InvalidClaims string

func (e InvalidClaims) Error() string {
	return string(e)
}

// FingerprintMismatch is an error indicating that a key fingerprint does
// not match the key.
type FingerprintMismatch struct {
	Given   string // The assumed fingerprint of the key
	Derived string // The actual fingerprint derived from the key
}

func (e *FingerprintMismatch) Error() string {
	return fmt.Sprintf("derived fingerprint %s for key with stated fingerprint %s", e.Derived, e.Given)
}
