package tokenstore

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
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

// parsedJsonNumToFloat converts a value of unknown type from parsed json into
// a float64
func parsedJsonNumToFloat(v interface{}) (float64, error) {
	switch tv := v.(type) {
	case json.Number:
		fv, err := tv.Float64()
		if err != nil {
			return 0, err
		}
		return fv, nil
	case float64:
		return tv, nil
	case int64:
		return float64(tv), nil
	default:
		return 0, fmt.Errorf("Unexpected type %T for expiration time", tv)
	}
}

// getTokenExp parses a JWT and reterns the expiration
func getTokenExp(token string, logger kslog.KsLogger) (time.Time, error) {
	tokenParts := strings.Split(token, ".")
	if nTokenParts := len(tokenParts); nTokenParts != 3 {
		err := ReceivedInvalidToken{
			Token:   token,
			Message: fmt.Sprintf("Token has %d parts instead of 3", nTokenParts),
		}
		logger.Errorf("Received invalid application token: %s", err)
		return time.Time{}, &err
	}
	claimsJson := make([]byte, base64.RawURLEncoding.DecodedLen(len(tokenParts[1])))
	_, err := base64.RawURLEncoding.Decode(claimsJson, []byte(tokenParts[1]))
	if err != nil {
		err := ReceivedInvalidToken{
			Token:   token,
			Message: fmt.Sprintf("Failed to decode claims base64: %s", err),
		}
		logger.Errorf("Received invalid application token: %s", err)
		return time.Time{}, &err
	}
	var claims map[string]interface{}
	err = json.Unmarshal(claimsJson, &claims)
	if err != nil {
		logger.Errorf("Failed to parse claims: %s", err)
		return time.Time{}, err
	}
	expVal := claims["exp"]
	if expVal == nil {
		err = fmt.Errorf("No `exp` in claims %s", claimsJson)
		logger.Error(err)
		return time.Time{}, err
	}
	expFloat, err := parsedJsonNumToFloat(expVal)
	if err != nil {
		return time.Time{}, err
	}
	expiration := timeutils.FloatToTime(expFloat)
	return expiration, nil
}

// getNewAppToken requests a new JWT and caches the token
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
	expiration, err := getTokenExp(signResp.Jwt, logger)
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

// getOrCreateAppToken will return a cached valid application token, or create
// a new applicationt token and add it to the cache
func (s *InstallTokenService) getOrCreateAppToken(app uint64, logger kslog.KsLogger) (*tokenpb.AppToken, error) {
	appToken, _, err := s.GetAppToken(app)
	if err != nil {
		logger.Errorf("Failed to get app %d token from store: %s", app, err)
		appToken = nil
	}
	if appToken != nil && !s.appTokenIsValid(appToken, logger) {
		appToken = nil
	}
	if appToken == nil {
		appToken, err = s.getNewAppToken(app, logger)
		if err != nil {
			return nil, err
		}
	}
	return appToken, nil
}

// createInstallToken provisions a new install token and stores it in the cache
func (s *InstallTokenService) createInstallToken(app, install uint64, appToken string, logger kslog.KsLogger) (*tokenpb.InstallToken, error) {
	installToken, expiration, err := s.InstallTokenProvider(install, appToken)
	if err != nil {
		logger.Errorf("Failed to get new token for app %d install %d: %s", app, install, err)
		return nil, err
	}
	pbexp, err := ptypes.TimestampProto(expiration)
	if err != nil {
		logger.Errorf("Failed to convert expiration %v to pb: %s", expiration, err)
		return nil, err
	}
	installTokenMsg := tokenpb.InstallToken{
		App:        app,
		Install:    install,
		Token:      installToken,
		Expiration: pbexp,
	}
	_, err = s.PutInstallToken(&installTokenMsg)
	if err != nil {
		logger.Errorf("Failed to put token for app %d install %d: %s", app, install, err)
	}
	return &installTokenMsg, nil
}

// GetInstallToken provices a valid install token for the requested installation.
// If a valid cached token is found, it will be returned, otherewise a new token
// will be be provisioned.
func (s *InstallTokenService) GetInstallToken(req *tokenpb.GetInstallTokenRequest, logger kslog.KsLogger) (*tokenpb.GetInstallTokenResponse, error) {
	if req.App == 0 {
		logger.Errorf("Attempted to add app %d", req.App)
		return nil, UnallowedAppId(req.App)
	}
	installToken, _, err := s.TokenMessageStore.GetInstallToken(req.App, req.Install)
	if err == nil && s.installTokenIsValid(installToken, logger) {
		resp := tokenpb.GetInstallTokenResponse{
			Token: installToken,
		}
		return &resp, nil
	}
	appToken, err := s.getOrCreateAppToken(req.App, logger)
	if err != nil {
		return nil, err
	}
	installToken, err = s.createInstallToken(req.App, req.Install, appToken.Token, logger)
	if err != nil {
		return nil, err
	}
	resp := tokenpb.GetInstallTokenResponse{
		Token: installToken,
	}
	return &resp, nil
}
