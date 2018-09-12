package keyutils

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os/exec"
	"strings"
	"unicode/utf8"
)

type UnparseableKey struct {
	Key     []byte
	Message string
}

func (e *UnparseableKey) Error() string {
	return e.Message
}

func ParsePrivateKey(key []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(key)
	if block != nil && block.Type != "RSA PRIVATE KEY" {
		err := &UnparseableKey{
			Key:     key,
			Message: fmt.Sprintf("PEM data of type %s is not an RSA PRIVATE KEY", block.Type),
		}
		return nil, err
	} else if block != nil {
		key = block.Bytes
	}
	rsaKey, err := x509.ParsePKCS1PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return rsaKey, rsaKey.Validate()
}

func KeyFingerprint(private *rsa.PrivateKey) (string, error) {
	privateDer := x509.MarshalPKCS1PrivateKey(private)
	cmd := exec.Command("openssl", "rsa", "-inform", "der", "-outform", "der", "-pubout")
	cmd.Stdin = bytes.NewReader(privateDer)
	publicBytes, err := cmd.Output()
	if err != nil {
		return "", err
	}
	fpBytes := sha1.Sum(publicBytes)
	pairs := make([]string, len(fpBytes))
	for i := 0; i < len(pairs); i++ {
		pairs[i] = fmt.Sprintf("%x", fpBytes[i])
	}
	return strings.Join(pairs, ":"), nil
}

type InvalidRune struct {
	C   rune
	Pos int
}

func (e *InvalidRune) Error() string {
	return fmt.Sprintf("Invalid character %c at position %d", e.C, e.Pos)
}

type BadOctetCount struct {
	Octets   int
	Expected int
}

func (e *BadOctetCount) Error() string {
	return fmt.Sprintf("expected %d octets but found %d", e.Expected, e.Octets)
}

type InvalidOctet struct {
	Octet string
	Pos  int
	Message string
}

func (e *InvalidOctet) Error() string {
	return fmt.Sprintf("Fingerpint group %d (%s) is invalid: %s", e.Pos+1, e.Octet, e.Message)
}

func ValidateFingerprintSha1(fingerprint string) error {
	validRunes := []rune{'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'a', 'b', 'c', 'd', 'e', 'f', ':'}
	for n, i, w := 1, 0, 0; i < len(fingerprint); n, i = n+1, i+w {
		runeVal, width := utf8.DecodeRuneInString(fingerprint[i:])
		foundRune := false
		for _, validRune := range validRunes {
			if runeVal != validRune {
				continue
			}
			foundRune = true
			break
		}
		if !foundRune {
			return &InvalidRune{runeVal, n}
		}
		w = width
	}
	parts := strings.Split(fingerprint, ":")
	const expectedOctets = 20
	if len(parts) != expectedOctets {
		return &BadOctetCount{len(parts), expectedOctets}
	}
	for i, part := range parts {
		if len(part) != 2 {
			var msg string
			if len(part) > 2 {
				msg = "octet is longer than two hex digits"
			} else if len(part) < 2 {
				msg = "octets must be zero padded to two digits"
			}
			return &InvalidOctet{part, i, msg}
		}
	}
	return nil
}
