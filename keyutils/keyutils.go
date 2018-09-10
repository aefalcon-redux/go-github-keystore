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
