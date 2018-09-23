package tokenstore

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

type InstallTokenProvider func(install uint64, appToken string) (string, time.Time, error)

type V3InstallTokenResp struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}

func V3InstallTokenProvider(install uint64, appToken string) (string, time.Time, error) {
	url := fmt.Sprintf("https://api.github.com/app/installations/%d/access_tokens", install)
	httpReq, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return "", time.Time{}, err
	}
	httpReq.Header.Add("Authorization", fmt.Sprintf("Bearer %s", appToken))
	httpReq.Header.Add("Accept", "application/vnd.github.machine-man-preview+json")
	httpResp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return "", time.Time{}, err
	}
	respEnt, err := ioutil.ReadAll(httpResp.Body)
	if err != nil {
		return "", time.Time{}, err
	}
	var tokenResp V3InstallTokenResp
	err = json.Unmarshal(respEnt, &tokenResp)
	if err != nil {
		return "", time.Time{}, err
	}
	if tokenResp.ExpiresAt == "" {
		return "", time.Time{}, fmt.Errorf("No expires_at in v3 response %s", respEnt)
	}
	if tokenResp.Token == "" {
		return "", time.Time{}, fmt.Errorf("No token in v3 response %s", respEnt)
	}
	expiration, err := time.Parse("2006-01-02T15:04:05Z", tokenResp.ExpiresAt)
	if err != nil {
		return "", time.Time{}, err
	}
	return tokenResp.Token, expiration, nil
}
