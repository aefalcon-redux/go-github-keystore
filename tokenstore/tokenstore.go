package tokenstore

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/aefalcon/github-keystore-protobuf/go/appkeypb"
	"github.com/aefalcon/github-keystore-protobuf/go/tokenpb"
	"github.com/aefalcon/go-github-keystore/keyservice"
	"github.com/aefalcon/go-github-keystore/kslog"
	"github.com/aefalcon/go-github-keystore/messagestore"
	"github.com/aefalcon/go-github-keystore/timeutils"
	"github.com/golang/protobuf/ptypes"
	structpb "github.com/golang/protobuf/ptypes/struct"
	"github.com/jtacoma/uritemplates"
)

type UnallowedAppId uint64

func (e UnallowedAppId) Error() string {
	return fmt.Sprintf("app id %d is not allowed", uint64(e))
}

type ReceivedInvalidToken struct {
	Token   string
	Message string
}

func (e *ReceivedInvalidToken) Error() string {
	return e.Message
}

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

type TokenMessageStore struct {
	messagestore.MessageStore
	tokenpb.Links
}

func NewTokenMessageStore(store messagestore.MessageStore, links *tokenpb.Links) *TokenMessageStore {
	if links == nil {
		links = &tokenpb.DefaultLinks
	}
	return &TokenMessageStore{
		MessageStore: store,
		Links:        *links,
	}
}

func (s *TokenMessageStore) AppTokenName(app uint64) (string, error) {
	uritmpl, err := uritemplates.Parse(s.Links.AppTokens)
	if err != nil {
		return "", err
	}
	return uritmpl.Expand(map[string]interface{}{
		"AppId": app,
	})
}

func (s *TokenMessageStore) InstallTokenName(app, install uint64) (string, error) {
	uritmpl, err := uritemplates.Parse(s.Links.AppTokens)
	if err != nil {
		return "", err
	}
	return uritmpl.Expand(map[string]interface{}{
		"AppId":     app,
		"InstallId": install,
	})
}

func (s *TokenMessageStore) GetAppToken(app uint64) (*tokenpb.AppToken, *messagestore.CacheMeta, error) {
	name, err := s.AppTokenName(app)
	if err != nil {
		return nil, nil, err
	}
	var token tokenpb.AppToken
	meta, err := s.GetMessage(name, &token)
	return &token, meta, err
}

func (s *TokenMessageStore) GetInstallToken(app, install uint64) (*tokenpb.InstallToken, *messagestore.CacheMeta, error) {
	name, err := s.InstallTokenName(app, install)
	if err != nil {
		return nil, nil, err
	}
	var token tokenpb.InstallToken
	meta, err := s.GetMessage(name, &token)
	return &token, meta, err
}

func (s *TokenMessageStore) PutAppToken(token *tokenpb.AppToken) (*messagestore.CacheMeta, error) {
	name, err := s.AppTokenName(token.App)
	if err != nil {
		return nil, err
	}
	return s.PutMessage(name, token)
}

func (s *TokenMessageStore) PutInstallToken(token *tokenpb.InstallToken) (*messagestore.CacheMeta, error) {
	name, err := s.InstallTokenName(token.App, token.Install)
	if err != nil {
		return nil, err
	}
	return s.PutMessage(name, token)
}

func (s *TokenMessageStore) DeleteAppToken(app uint64) (*messagestore.CacheMeta, error) {
	name, err := s.AppTokenName(app)
	if err != nil {
		return nil, err
	}
	return s.DeleteMessage(name)
}

func (s *TokenMessageStore) DeleteInstallToken(app, install uint64) (*messagestore.CacheMeta, error) {
	name, err := s.InstallTokenName(app, install)
	if err != nil {
		return nil, err
	}
	return s.DeleteMessage(name)
}

type InstallTokenService struct {
	*TokenMessageStore
	keyservice.SigningService
	InstallTokenProvider
}

func (s *InstallTokenService) installTokenIsValid(tokenMsg *tokenpb.InstallToken, logger kslog.KsLogger) bool {
	expiration, err := ptypes.Timestamp(tokenMsg.Expiration)
	if err != nil {
		logger.Errorf("Failed to parse fetched install token's expiration: %s", err)
		return false
	}
	now := time.Now()
	if now.After(expiration) {
		logger.Errorf("Fetched install token is expired")
		return false
	}
	return true
}

func (s *InstallTokenService) appTokenIsValid(tokenMsg *tokenpb.AppToken, logger kslog.KsLogger) bool {
	expiration, err := ptypes.Timestamp(tokenMsg.Expiration)
	if err != nil {
		logger.Errorf("Failed to parse fetched app token's expiration: %s", err)
		return false
	}
	now := time.Now()
	if now.After(expiration) {
		logger.Errorf("Fetched app token is expired")
		return false
	}
	return true
}

func (s *InstallTokenService) getNewAppToken(app uint64, logger kslog.KsLogger) (*tokenpb.AppToken, error) {
	now := time.Now().UTC()
	signReq := appkeypb.SignJwtRequest{
		App:       app,
		Algorithm: "RS256",
		Claims: &structpb.Struct{
			Fields: map[string]*structpb.Value{
				"iss": &structpb.Value{
					Kind: &structpb.Value_StringValue{
						StringValue: fmt.Sprintf("%d", app),
					},
				},
				"exp": &structpb.Value{
					Kind: &structpb.Value_NumberValue{
						NumberValue: float64(int64(timeutils.TimeToFloat(now.Add(time.Minute * 9)))), // Github says it wants Numreric, but it specifically wants int
					},
				},
			},
		},
	}
	signResp, err := s.SignJwt(&signReq, logger)
	if err != nil {
		logger.Errorf("Failed to get new token for app %d: %s", app, err)
		return nil, err
	}
	tokenParts := strings.Split(signResp.Jwt, ".")
	if nTokenParts := len(tokenParts); nTokenParts != 3 {
		err := ReceivedInvalidToken{
			Token:   signResp.Jwt,
			Message: fmt.Sprintf("Token has %d parts instead of 3", nTokenParts),
		}
		logger.Errorf("Received invalid application token: %s", err)
		return nil, &err
	}
	claimsJson := make([]byte, base64.RawURLEncoding.DecodedLen(len(tokenParts[1])))
	_, err = base64.RawURLEncoding.Decode(claimsJson, []byte(tokenParts[1]))
	if err != nil {
		err := ReceivedInvalidToken{
			Token:   signResp.Jwt,
			Message: fmt.Sprintf("Failed to decode claims base64: %s", err),
		}
		logger.Errorf("Received invalid application token: %s", err)
		return nil, &err
	}
	var claims map[string]interface{}
	err = json.Unmarshal(claimsJson, &claims)
	if err != nil {
		logger.Errorf("Failed to parse claims: %s", err)
		return nil, err
	}
	expVal := claims["exp"]
	if expVal == nil {
		err = fmt.Errorf("No `exp` in claims %s", claimsJson)
		logger.Error(err)
		return nil, err
	}
	var expFloat float64
	switch tExp := expVal.(type) {
	case json.Number:
		expFloat, err = tExp.Float64()
		if err != nil {
			return nil, err
		}
	case float64:
		expFloat = tExp
	case int64:
		expFloat = float64(tExp)
	default:
		return nil, fmt.Errorf("Unexpected type %T for expiration time", tExp)
	}
	expiration := timeutils.FloatToTime(expFloat)
	pbexp, err := ptypes.TimestampProto(expiration)
	if err != nil {
		logger.Errorf("Failed to convert expiration %v of new app token to pb time", expiration, err)
		return nil, err
	}
	appTokenMsg := &tokenpb.AppToken{
		App:        app,
		Token:      signResp.Jwt,
		Expiration: pbexp,
	}
	_, err = s.PutAppToken(appTokenMsg)
	if err != nil {
		logger.Errorf("Failed to put app token: %s", err)
	}
	return appTokenMsg, nil
}

func (s *InstallTokenService) GetInstallToken(req *tokenpb.GetInstallTokenRequest, logger kslog.KsLogger) (*tokenpb.GetInstallTokenResponse, error) {
	if req.App == 0 {
		logger.Errorf("Attempted to add app %d", req.App)
		return nil, UnallowedAppId(req.App)
	}
	installTokenMsg, _, err := s.TokenMessageStore.GetInstallToken(req.App, req.Install)
	if err == nil && s.installTokenIsValid(installTokenMsg, logger) {
		resp := tokenpb.GetInstallTokenResponse{
			Token: installTokenMsg,
		}
		return &resp, nil
	}
	appTokenMsg, _, err := s.GetAppToken(req.App)
	if err != nil {
		logger.Errorf("Failed to get app %d token from store: %s", req.App, err)
		appTokenMsg = nil
	}
	if appTokenMsg != nil && !s.appTokenIsValid(appTokenMsg, logger) {
		appTokenMsg = nil
	}
	if appTokenMsg == nil {
		appTokenMsg, err = s.getNewAppToken(req.App, logger)
		if err != nil {
			return nil, err
		}
	}
	installToken, expiration, err := s.InstallTokenProvider(req.Install, string(appTokenMsg.Token))
	if err != nil {
		logger.Errorf("Failed to get new token for app %d install %d: %s", req.App, req.Install, err)
		return nil, err
	}
	pbexp, err := ptypes.TimestampProto(expiration)
	if err != nil {
		logger.Errorf("Failed to convert expiration %v to pb: %s", expiration, err)
		return nil, err
	}
	installTokenMsg = &tokenpb.InstallToken{
		App:        req.App,
		Install:    req.Install,
		Token:      installToken,
		Expiration: pbexp,
	}
	_, err = s.PutInstallToken(installTokenMsg)
	if err != nil {
		logger.Errorf("Failed to put token for app %d install %d: %s", req.App, req.Install, err)
	}
	resp := tokenpb.GetInstallTokenResponse{
		Token: installTokenMsg,
	}
	return &resp, nil
}
