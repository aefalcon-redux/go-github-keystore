package appkeystore

import (
	"fmt"
)

type AppExists uint64

func (e AppExists) Error() string {
	return fmt.Sprintf("app %d already exists", uint64(e))
}

type UnallowedAppId uint64

func (e UnallowedAppId) Error() string {
	return fmt.Sprintf("app id %d is not allowed", uint64(e))
}

type UnsupportedSignatureAlgo string

func (e UnsupportedSignatureAlgo) Error() string {
	return fmt.Sprintf("unsupported algorithm %s", string(e))
}

type NoKeyForApp uint64

func (e NoKeyForApp) Error() string {
	return fmt.Sprintf("No key for app %d", uint64(e))
}

type InvalidClaims string

func (e InvalidClaims) Error() string {
	return string(e)
}

type FingerprintMismatch struct {
	Given   string
	Derived string
}

func (e *FingerprintMismatch) Error() string {
	return fmt.Sprintf("derived fingerprint %s for key with stated fingerprint %s", e.Derived, e.Given)
}
