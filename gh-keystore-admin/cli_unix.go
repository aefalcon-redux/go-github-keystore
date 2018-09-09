package main

import (
	"os/user"
	"path/filepath"
	"strings"
)

func expandPath(path string) (string, error) {
	if strings.HasPrefix(path, "~") {
		currentUser, err := user.Current()
		if err != nil {
			return "", err
		}
		return filepath.Clean(filepath.Join(currentUser.HomeDir, path[1:])), nil
	}
	return path, nil
}
