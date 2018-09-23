// Manage data in an application key store backed by a message store
// and generate JWT
package appkeystore

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/aefalcon/github-keystore-protobuf/go/appkeypb"
	"github.com/aefalcon/go-github-keystore/keyservice"
	"github.com/aefalcon/go-github-keystore/keyutils"
	"github.com/aefalcon/go-github-keystore/kslog"
	"github.com/aefalcon/go-github-keystore/messagestore"
	"github.com/aefalcon/go-github-keystore/timeutils"
	"github.com/golang/protobuf/jsonpb"
	structpb "github.com/golang/protobuf/ptypes/struct"
	"github.com/jtacoma/uritemplates"
)

// StoreBackend is the interface that must be implemented by a storage
// system to be used by AppKeyStore.
type StoreBackend interface {
	messagestore.BlobStore
	messagestore.MessageStore
}

// AppKeyStore manages a list of applications and their keys
type AppKeyStore struct {
	StoreBackend                // Storage system
	Links        appkeypb.Links // Definitions of paths in the store
}

// NewAppKeyStore allocates a new AppKeyStore.  Generally nil should be
// passed for links, but a specific links may be provided.
func NewAppKeyStore(backend StoreBackend, links *appkeypb.Links) *AppKeyStore {
	if links == nil {
		links = &appkeypb.DefaultLinks
	}
	return &AppKeyStore{
		StoreBackend: backend,
		Links:        *links,
	}
}

// InitDb initializes an empty database.  This must be called before
// database use.
func (s *AppKeyStore) InitDb(logger kslog.KsLogger) error {
	var index appkeypb.AppIndex
	_, err := s.PutAppIndex(&index)
	if err != nil {
		logger.Error("Failed to put application index")
	}
	return err
}

// appIndexName gets the name of the applicatoin index within the
// storage system
func (s *AppKeyStore) appIndexName() (string, error) {
	uritmpl, err := uritemplates.Parse(s.Links.AppIndex)
	if err != nil {
		return "", err
	}
	return uritmpl.Expand(map[string]interface{}{})
}

// GetAppIndex fetches the applicatoin index from storage
func (s *AppKeyStore) GetAppIndex() (*appkeypb.AppIndex, *messagestore.CacheMeta, error) {
	name, err := s.appIndexName()
	if err != nil {
		return nil, nil, err
	}
	var index appkeypb.AppIndex
	meta, err := s.GetMessage(name, &index)
	return &index, meta, err
}

// PutAppIndex creates or replaces the appication index in storage
func (s *AppKeyStore) PutAppIndex(index *appkeypb.AppIndex) (*messagestore.CacheMeta, error) {
	name, err := s.appIndexName()
	if err != nil {
		return nil, err
	}
	return s.PutMessage(name, index)
}

// DeleteAppIndex removes the app index from storage
func (s *AppKeyStore) DeleteAppIndex() (*messagestore.CacheMeta, error) {
	name, err := s.appIndexName()
	if err != nil {
		return nil, err
	}
	return s.DeleteMessage(name)
}

// appName gets the name of the document describing an application within the
// storage system
func (s *AppKeyStore) appName(appId uint64) (string, error) {
	uritmpl, err := uritemplates.Parse(s.Links.App)
	if err != nil {
		return "", err
	}
	return uritmpl.Expand(map[string]interface{}{"AppId": appId})
}

// GetApp fetches the document describing an application from storage
func (s *AppKeyStore) GetApp(appId uint64) (*appkeypb.App, *messagestore.CacheMeta, error) {
	name, err := s.appName(appId)
	if err != nil {
		return nil, nil, err
	}
	var app appkeypb.App
	meta, err := s.GetMessage(name, &app)
	return &app, meta, err
}

// PutApp creates or replaces the document describing an application in storage
func (s *AppKeyStore) PutApp(app *appkeypb.App) (*messagestore.CacheMeta, error) {
	name, err := s.appName(app.Id)
	if err != nil {
		return nil, err
	}
	return s.PutMessage(name, app)
}

// DeleteApp removes the document describing an application from storage
func (s *AppKeyStore) DeleteApp(appId uint64) (*messagestore.CacheMeta, error) {
	name, err := s.appName(appId)
	if err != nil {
		return nil, err
	}
	return s.DeleteMessage(name)
}

// keyName gets the name of an RSA key for a certain application within the
// storage system
func (s *AppKeyStore) keyName(appId uint64, fingerprint string) (string, error) {
	uritmpl, err := uritemplates.Parse(s.Links.Key)
	if err != nil {
		return "", err
	}
	return uritmpl.Expand(map[string]interface{}{"AppId": appId, "Fingerprint": fingerprint})
}

// GetKey loads the key for a specified app given the key's finger print.
func (s *AppKeyStore) GetKey(appId uint64, fingerprint string) ([]byte, *messagestore.CacheMeta, error) {
	name, err := s.keyName(appId, fingerprint)
	if err != nil {
		return nil, nil, err
	}
	return s.GetBlob(name)
}

// PutKey stores a key for an app using a specified fingerprint.
func (s *AppKeyStore) PutKey(app uint64, fingerprint string, key []byte) (*messagestore.CacheMeta, error) {
	name, err := s.keyName(app, fingerprint)
	if err != nil {
		return nil, err
	}
	return s.PutBlob(name, key)
}

// DeleteKey removes the key specified by fingerprint from an app
func (s *AppKeyStore) DeleteKey(appId uint64, fingerprint string) (*messagestore.CacheMeta, error) {
	name, err := s.keyName(appId, fingerprint)
	if err != nil {
		return nil, err
	}
	return s.DeleteBlob(name)
}

// kyeMetaName gets the name used to reference an RSA key metadata for
// a particular RSA key and application
func (s *AppKeyStore) keyMetaName(appId uint64, fingerprint string) (string, error) {
	uritmpl, err := uritemplates.Parse(s.Links.KeyMeta)
	if err != nil {
		return "", err
	}
	return uritmpl.Expand(map[string]interface{}{"AppId": appId, "Fingerprint": fingerprint})
}

// GetKeyMeta fetches key metadata for an applications key, identified by fingerprint
func (s *AppKeyStore) GetKeyMeta(appId uint64, fingerprint string) (*appkeypb.AppKeyMeta, *messagestore.CacheMeta, error) {
	name, err := s.keyMetaName(appId, fingerprint)
	if err != nil {
		return nil, nil, err
	}
	var appMeta appkeypb.AppKeyMeta
	cacheMeta, err := s.GetMessage(name, &appMeta)
	return &appMeta, cacheMeta, err
}

// PutKeyMeta creates or replaces a keys metadta
func (s *AppKeyStore) PutKeyMeta(keyMeta *appkeypb.AppKeyMeta) (*messagestore.CacheMeta, error) {
	name, err := s.keyMetaName(keyMeta.App, keyMeta.Fingerprint)
	if err != nil {
		return nil, err
	}
	return s.PutMessage(name, keyMeta)
}

// DeleteKeyMeta removes the metadata for a specified key
func (s *AppKeyStore) DeleteKeyMeta(appId uint64, fingerprint string) (*messagestore.CacheMeta, error) {
	name, err := s.keyMetaName(appId, fingerprint)
	if err != nil {
		return nil, err
	}
	return s.DeleteBlob(name)
}

// AppKeyService performs high level functions on data stored in an
// AppKeyStore
type AppKeyService struct {
	Store *AppKeyStore
}

// NewAppKeyService allocates a new app key store.  The arguments are passed
// through to NewAppKeyService
func NewAppKeyService(backend StoreBackend, links *appkeypb.Links) *AppKeyService {
	return &AppKeyService{
		Store: NewAppKeyStore(backend, links),
	}
}

// Guarantee AppKeyService implements needed interfaces
var _ keyservice.ManagerService = &AppKeyService{}
var _ keyservice.SigningService = &AppKeyService{}

// AddApp adds an app to the data store, including it in the application index
func (s *AppKeyService) AddApp(req *appkeypb.AddAppRequest, logger kslog.KsLogger) (*appkeypb.AddAppResponse, error) {
	if req.App == 0 {
		logger.Errorf("Attempted to add app %d", req.App)
		return nil, UnallowedAppId(req.App)
	}
	index, _, err := s.Store.GetAppIndex()
	if err != nil {
		return nil, err
	}
	if _, found := index.AppRefs[req.App]; found {
		return nil, AppExists(req.App)
	}
	if index.AppRefs == nil {
		index.AppRefs = make(map[uint64]*appkeypb.AppIndexEntry)
	}
	index.AppRefs[req.App] = &appkeypb.AppIndexEntry{
		Id: req.App,
	}
	app := appkeypb.App{
		Id: req.App,
	}
	if len(req.Keys) > 0 {
		app.Keys = make(map[string]*appkeypb.AppKeyIndexEntry, len(req.Keys))
		for _, reqKey := range req.Keys {
			rsaKey, err := keyutils.ParsePrivateKey(reqKey.Key)
			if err != nil {
				return nil, err
			}
			fingerprint, err := keyutils.KeyFingerprint(rsaKey)
			if err != nil {
				return nil, err
			}
			if reqKey.Meta.Fingerprint != fingerprint {
				return nil, &FingerprintMismatch{
					Given:   reqKey.Meta.Fingerprint,
					Derived: fingerprint,
				}
			}
			app.Keys[fingerprint] = &appkeypb.AppKeyIndexEntry{
				Meta: reqKey.Meta,
			}
		}
		for _, reqKey := range req.Keys {
			_, err = s.Store.PutKey(req.App, reqKey.Meta.Fingerprint, reqKey.Key)
			if err != nil {
				logger.Logf("Failed to put key in store: %s", err)
				return nil, err
			}
			_, err = s.Store.PutKeyMeta(reqKey.Meta)
			if err != nil {
				logger.Logf("Failed to put key metadata in store: %s", err)
				return nil, err
			}
		}
	}
	_, err = s.Store.PutApp(&app)
	if err != nil {
		return nil, err
	}
	_, err = s.Store.PutAppIndex(index)
	if err != nil {
		return nil, err
	}
	return &appkeypb.AddAppResponse{}, nil
}

// RemoveApp removes an application from the store, removing all its keys and
// its reference in the application index
func (s *AppKeyService) RemoveApp(req *appkeypb.RemoveAppRequest, logger kslog.KsLogger) (*appkeypb.RemoveAppResponse, error) {
	if req.App == 0 {
		logger.Errorf("Attempted to add app %d", req.App)
		return nil, UnallowedAppId(req.App)
	}
	index, _, err := s.Store.GetAppIndex()
	if err != nil {
		logger.Errorf("failed to get app index: %s", err)
		return nil, err
	}
	if _, found := index.AppRefs[req.App]; !found {
		logger.Errorf("Application %d not in index", req.App)
	} else {
		delete(index.AppRefs, req.App)
		_, err = s.Store.PutAppIndex(index)
		if err != nil {
			logger.Error("Failed to put updated application index")
			return nil, err
		}
		logger.Logf("Application %d removed from index", req.App)
	}
	app, _, err := s.Store.GetApp(req.App)
	if err != nil {
		logger.Errorf("Failed to get app %d: %s", req.App, err)
		return nil, err
	} else {
		logger.Logf("Fetched app from store for %d", req.App)
	}
	_, err = s.Store.DeleteApp(req.App)
	if err != nil {
		logger.Logf("Failed to remove app from store for %d: %s", req.App, err)
		return nil, err
	}
	logger.Logf("Deleted application %d", req.App)
	removeKeysOk := true
	if len(app.Keys) == 0 {
		logger.Logf("no keys to delete")
		return &appkeypb.RemoveAppResponse{}, nil
	}
	for _, key := range app.Keys {
		_, err = s.Store.DeleteKeyMeta(req.App, key.Meta.Fingerprint)
		if err != nil {
			logger.Logf("Failed to remove key %s metadata", key.Meta.Fingerprint)
			removeKeysOk = false
		} else {
			logger.Logf("Deleted key %s metadata", key.Meta.Fingerprint)
		}
		_, err = s.Store.DeleteKey(req.App, key.Meta.Fingerprint)
		if err != nil {
			logger.Logf("Failed to remove key %s", key.Meta.Fingerprint)
			removeKeysOk = false
		} else {
			logger.Logf("Deleted key %s", key.Meta.Fingerprint)
		}
	}
	if !removeKeysOk {
		return nil, fmt.Errorf("Failed to remove keys")
	} else {
		logger.Logf("Deleted all keys")
	}
	return &appkeypb.RemoveAppResponse{}, nil
}

// GetApp loads an application description from the store.  This includes an
// index of keys for the application.
func (s *AppKeyService) GetApp(req *appkeypb.GetAppRequest, logger kslog.KsLogger) (*appkeypb.App, error) {
	app, _, err := s.Store.GetApp(req.App)
	if err != nil {
		logger.Logf("Failed to get app %d: %s", req.App, err)
		return nil, err
	}
	return app, err
}

// ListApps loads the application index for the data store
func (s *AppKeyService) ListApps(req *appkeypb.ListAppsRequest, logger kslog.KsLogger) (*appkeypb.AppIndex, error) {
	index, _, err := s.Store.GetAppIndex()
	if err != nil {
		logger.Logf("Failed to get application index: %s", err)
		return nil, err
	}
	return index, err
}

// AddKey adds a key to the data store and updates an application to reference it.
func (s *AppKeyService) AddKey(req *appkeypb.AddKeyRequest, logger kslog.KsLogger) (*appkeypb.AddKeyResponse, error) {
	if len(req.Keys) == 0 {
		logger.Logf("No keys to add")
		return &appkeypb.AddKeyResponse{}, nil
	}
	app, _, err := s.Store.GetApp(req.App)
	if err != nil {
		logger.Logf("Failed to get app %d: %s", req.App, err)
		return nil, err
	}
	logger.Logf("Adding %d keys", len(req.Keys))
	if len(app.Keys) == 0 {
		app.Keys = make(map[string]*appkeypb.AppKeyIndexEntry)
	}
	keysToAdd := make([]*appkeypb.AppKey, 0, len(req.Keys))
	for _, key := range req.Keys {
		if _, found := app.Keys[key.Meta.Fingerprint]; found {
			logger.Logf("App %d already has key %s", req.App, key.Meta.Fingerprint)
			continue
		}
		key.Meta.App = req.App
		app.Keys[key.Meta.Fingerprint] = &appkeypb.AppKeyIndexEntry{
			Meta: key.Meta,
		}
		keysToAdd = append(keysToAdd, key)
	}
	for _, key := range keysToAdd {
		logger.Logf("Adding key %s", key.Meta.Fingerprint)
		_, err = s.Store.PutKey(req.App, key.Meta.Fingerprint, key.Key)
		if err != nil {
			logger.Logf("Failed to put key in store: %s", err)
			return nil, err
		}
		logger.Logf("Added key %s", key.Meta.Fingerprint)
		_, err = s.Store.PutKeyMeta(key.Meta)
		if err != nil {
			logger.Logf("Failed to put key metadata in store: %s", err)
			return nil, err
		}
		logger.Logf("Added key metadata for %s", key.Meta.Fingerprint)
	}
	_, err = s.Store.PutApp(app)
	if err != nil {
		logger.Logf("Failed to update application in store: %s", err)
		return nil, err
	}
	return &appkeypb.AddKeyResponse{}, nil
}

// RemoveKey removes a key from the data store and its reference to an application.
func (s *AppKeyService) RemoveKey(req *appkeypb.RemoveKeyRequest, logger kslog.KsLogger) (*appkeypb.RemoveKeyResponse, error) {
	for _, fingerprint := range req.Fingerprints {
		_, err := s.Store.DeleteKey(req.App, fingerprint)
		if err != nil {
			logger.Logf("Failed delete key %s: %s", fingerprint, err)
		}
		_, err = s.Store.DeleteKeyMeta(req.App, fingerprint)
		if err != nil {
			logger.Logf("Failed delete key %s metadata: %s", fingerprint, err)
		}
	}
	app, _, err := s.Store.GetApp(req.App)
	if err != nil {
		logger.Logf("Failed to get app %d: %s", req.App, err)
		return nil, err
	}
	for _, fingerprint := range req.Fingerprints {
		if _, found := app.Keys[fingerprint]; !found {
			logger.Errorf("App %d does not have  key %s", req.App, fingerprint)
		}
		delete(app.Keys, fingerprint)
	}
	_, err = s.Store.PutApp(app)
	if err != nil {
		logger.Errorf("Failed to update application in store: %s", err)
	}
	return &appkeypb.RemoveKeyResponse{}, nil
}

// anyKeyFromApp fetches a valid key for a specified app.  This is useful
// when a key operation needs to be performed and any valid key
// may be used.
func (s *AppKeyService) anyKeyFromApp(app *appkeypb.App, logger kslog.KsLogger) (*rsa.PrivateKey, string, error) {
	var key []byte
	var fingerprint string
	for _, keyEntry := range app.Keys {
		if keyEntry.Meta.Disabled {
			continue
		}
		var err error
		key, _, err = s.Store.GetKey(app.Id, keyEntry.Meta.Fingerprint)
		if err != nil {
			logger.Logf("Failed to get key %s for app %d", keyEntry.Meta.Fingerprint, app.Id)
		}
		fingerprint = keyEntry.Meta.Fingerprint
		break
	}
	if key == nil {
		logger.Logf("Did not find a key for app %d", app.Id)
		return nil, "", NoKeyForApp(app.Id)
	}
	rsaKey, err := keyutils.ParsePrivateKey(key)
	if err != nil {
		logger.Logf("Failed to parse private key %s: %s", fingerprint, err)
		return nil, "", err
	}
	return rsaKey, fingerprint, nil
}

// validateIssClaim checks that the `iss` (issuer) claim of a JWT is a string
// representation of the application id.
func validateIssClaim(app uint64, iss string) error {
	issAsInt, err := strconv.ParseUint(iss, 10, 64)
	if err != nil {
		return InvalidClaims(fmt.Sprintf("Could not parse `iss` to int: %s", err))
	}
	if app != issAsInt {
		return InvalidClaims(fmt.Sprintf("Application Id in request (%d) does not match claim `iss` (%d)", app, issAsInt))
	}
	return nil
}

// validateExpNbfClaims checks the `exp` (expires) and `nbf` (not before)
// claims of a JWT.  `exp` must be in the future and `nbf` must be after
// `exp`.  `nbf` must also be either in the feature or within a reasonable
// margin of now in the past (5 seconds ago).
func validateExpNbfClaims(exp, nbf, now time.Time) error {
	if !exp.After(now) {
		return InvalidClaims("`exp` indicates claims are already expired")
	}
	if !nbf.IsZero() {
		if !exp.After(nbf) {
			return InvalidClaims("`exp` must be greater than `nbf`")
		}
		if nbf.Before(now) && now.Sub(nbf) > time.Second*5 {
			return InvalidClaims("`nbf` is more than 5 seconds in the past")
		}
	}
	return nil
}

// pbValToStr converts a structpb.Value to a string.  The structpb.Value
// must actctually be a StringValue
func pbValToStr(v *structpb.Value) (string, bool) {
	stringVal, ok := v.Kind.(*structpb.Value_StringValue)
	if !ok {
		return "", false
	}
	return stringVal.StringValue, true
}

// pbValToNum converts a astructpb.Value to a float64.  The structpb.Value
// must actually be a NumberValue.
func pbValToNum(v *structpb.Value) (float64, bool) {
	numVal, ok := v.Kind.(*structpb.Value_NumberValue)
	if !ok {
		return 0.0, false
	}
	return numVal.NumberValue, true
}

// pbValToTime converts a astructpb.Value to a time.Time.  The structpb.Value
// must be a NumberValue and represents the number of senconds since
// 1970-01-01T00:00:00Z
func pbValToTime(v *structpb.Value) (time.Time, bool) {
	numTime, ok := pbValToNum(v)
	if !ok {
		return time.Time{}, false
	}
	return timeutils.FloatToTime(numTime), true
}

// validateClaims checks the claims in a `appkeypb.SignJwtRequest` to make sure
// all values are sane and secure
func validateClaims(req *appkeypb.SignJwtRequest, now time.Time) error {
	issVal := req.Claims.Fields["iss"]
	if issVal == nil {
		return InvalidClaims("Missing claim `iss`")
	}
	iss, ok := pbValToStr(issVal)
	if !ok {
		return InvalidClaims("`iss` must be string")
	}
	if err := validateIssClaim(req.App, iss); err == nil {
		return err
	}
	expVal := req.Claims.Fields["exp"]
	if expVal == nil {
		return InvalidClaims("Missing claim `exp`")
	}
	exp, ok := pbValToTime(expVal)
	if !ok {
		return InvalidClaims("`exp` must be numeric")
	}
	nbfVal, ok := req.Claims.Fields["nbf"]
	var nbf time.Time
	if nbfVal != nil {
		nbf, ok = pbValToTime(nbfVal)
		if !ok {
			return InvalidClaims("`nbf` must be numeric")
		}
	}
	if err := validateExpNbfClaims(exp, nbf, now); err != nil {
		return err
	}
	iatVal := req.Claims.Fields["iat"]
	if iatVal != nil {
		return InvalidClaims("Do not include `iat` in claims")
	}
	return nil
}

// SignJwt loads a key for a specified app and signs the provided claims
func (s *AppKeyService) SignJwt(req *appkeypb.SignJwtRequest, logger kslog.KsLogger) (*appkeypb.SignJwtResponse, error) {
	if req.Algorithm != "RS256" {
		return nil, UnsupportedSignatureAlgo(req.Algorithm)
	}
	now := time.Now().UTC()
	err := validateClaims(req, now)
	if err != nil {
		logger.Errorf("Claims are invalid: %s", err)
		return nil, err
	}
	app, _, err := s.Store.GetApp(req.App)
	if err != nil {
		logger.Errorf("Failed to get application from store: %s", err)
		return nil, err
	}
	rsaKey, fingerprint, err := s.anyKeyFromApp(app, logger)
	if err != nil {
		logger.Errorf("Failed to get key for app %d: %s", req.App, err)
		return nil, err
	}
	req.Claims.Fields["iat"] = &structpb.Value{
		Kind: &structpb.Value_NumberValue{
			NumberValue: float64(int64(timeutils.TimeToFloat(now))),
		},
	}
	req.Claims.Fields["com.mobettersoftware.auth-kid"] = &structpb.Value{
		Kind: &structpb.Value_StringValue{
			StringValue: fingerprint,
		},
	}
	jsonMarshaler := jsonpb.Marshaler{
		Indent: "",
	}
	claims, err := jsonMarshaler.MarshalToString(req.Claims)
	if err != nil {
		logger.Errorf("Failed to marshal claims: %s", err)
		return nil, err
	}
	claims64 := make([]byte, base64.RawURLEncoding.EncodedLen(len(claims)))
	base64.RawURLEncoding.Encode(claims64, []byte(claims))
	header, err := json.Marshal(map[string]interface{}{
		"typ": "JWT",
		"alg": req.Algorithm,
	})
	if err != nil {
		logger.Errorf("Failed to marshal header: %s", err)
	}
	header64 := make([]byte, base64.RawURLEncoding.EncodedLen(len(header)))
	base64.RawURLEncoding.Encode(header64, []byte(header))
	secureData := make([]byte, len(claims64)+len(header64)+1)
	copy(secureData, header64)
	secureData[len(header64)] = '.'
	copy(secureData[len(header64)+1:], claims64)
	// sign with RSASSA-PKCS1-V1_5-SIGN using SHA-256
	digest := sha256.Sum256(secureData)
	sig, err := rsa.SignPKCS1v15(nil, rsaKey, crypto.SHA256, digest[:])
	if err != nil {
		logger.Logf("Failed to sign claims data: %s", err)
		return nil, err
	}
	token := make([]byte, len(secureData)+1+base64.RawURLEncoding.EncodedLen(len(sig)))
	copy(token, secureData)
	token[len(secureData)] = '.'
	base64.RawURLEncoding.Encode(token[len(secureData)+1:], sig[:])
	resp := appkeypb.SignJwtResponse{
		Jwt: string(token),
	}
	return &resp, nil
}
