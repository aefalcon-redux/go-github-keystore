package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"unicode"
	"unicode/utf8"

	"github.com/aefalcon/github-keystore-protobuf/go/appkeypb"
	"github.com/aefalcon/go-github-keystore/docstore"
	"github.com/aefalcon/go-github-keystore/keyutils"
	"github.com/aefalcon/go-github-keystore/kslog"
	"github.com/aefalcon/go-github-keystore/s3store"
	"github.com/golang/protobuf/jsonpb"
)

const (
	FLAG_CONFIG       = "config"
	FLAG_INDEX_URL    = "index-url"
	FLAG_INDEX_BUCKET = "index-bucket"
	FLAG_INDEX_KEY    = "index-key"
	FLAG_AWS_REGION   = "aws-region"
	FLAG_APP          = "app"
	FLAG_KEY_FILE     = "key-file"
	FLAG_KEY          = "key"

	CMD_INIT_CONFIG = "init-config"
	CMD_INIT_DB     = "init-db"
	CMD_LIST_APPS   = "list-apps"
	CMD_ADD_APP     = "add-app"
	CMD_ADD_KEY     = "add-key"
	CMD_LIST_KEYS   = "list-keys"
	CMD_REM_KEY     = "remove-key"
	CMD_REM_APP     = "remove-app"
)

type flagValues struct {
	ConfigPath  string
	IndexUrl    string
	IndexBucket string
	IndexKey    string
	AwsRegion   string
	App         uint64
	KeyFile     string
	Key         string
}

func (v flagValues) RequireUint64(flag string, value uint64) error {
	if value == 0 {
		return fmt.Errorf("flag --%s must not be zero", flag)
	}
	return nil
}

func (v flagValues) RequireString(flag string, value string) error {
	if value == "" {
		return fmt.Errorf("flag --%s must be set", flag)
	}
	return nil
}

func (v *flagValues) Require(flags ...string) error {
	for _, flag := range flags {
		var err error
		switch flag {
		case FLAG_APP:
			err = v.RequireUint64(flag, v.App)
		case FLAG_CONFIG:
			err = v.RequireString(flag, v.ConfigPath)
		case FLAG_INDEX_URL:
			err = v.RequireString(flag, v.IndexUrl)
		case FLAG_INDEX_BUCKET:
			err = v.RequireString(flag, v.IndexBucket)
		case FLAG_INDEX_KEY:
			err = v.RequireString(flag, v.IndexKey)
		case FLAG_AWS_REGION:
			err = v.RequireString(flag, v.AwsRegion)
		case FLAG_KEY_FILE:
			err = v.RequireString(flag, v.KeyFile)
		case FLAG_KEY:
			err = v.RequireString(flag, v.Key)
		default:
			return fmt.Errorf("Unknown flag %s", flag)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func MakeStore(config *appkeypb.AppKeyManagerConfig, links *appkeypb.Links) (*docstore.AppKeyStore, error) {
	if links == nil {
		links = &appkeypb.DefaultLinks
	}
	blobStore, err := s3store.NewS3BlobStore(config.DbLoc)
	if err != nil {
		return nil, err
	}
	docStore := docstore.BlobDocStore{
		BlobStore: blobStore,
	}
	store := docstore.NewAppKeyStore(&docStore, links)
	return store, nil
}

func GetConfig(flags *flagValues, logger kslog.KsLogger) (*appkeypb.AppKeyManagerConfig, error) {
	configPath, err := expandPath(flags.ConfigPath)
	if err != nil {
		logger.Logf("Unable to expand path %s: %s", flags.ConfigPath, err)
		return nil, err
	}
	configFile, err := os.Open(configPath)
	if err != nil {
		logger.Logf("Unable to open configuration file %s: %s", configPath, err)
		return nil, err
	}
	defer configFile.Close()
	var config appkeypb.AppKeyManagerConfig
	unmarshaler := jsonpb.Unmarshaler{}
	err = unmarshaler.Unmarshal(configFile, &config)
	if err != nil {
		logger.Logf("Unable to unmarshal confguration: %s", err)
		return nil, err
	}
	return &config, nil
}

type CheckFlagsFunc func(flagValues *flagValues) error

func CheckAll(funcs ...CheckFlagsFunc) CheckFlagsFunc {
	return func(flagValues *flagValues) error {
		for _, checkFunc := range funcs {
			err := checkFunc(flagValues)
			if err != nil {
				return err
			}
		}
		return nil
	}
}

func ValidateInitConfig(fv *flagValues) error {
	if fv.IndexUrl == "" && fv.IndexBucket == "" && fv.IndexKey == "" {
		return fmt.Errorf("Either --%s or both --%s and --%s must be used", FLAG_INDEX_URL, FLAG_INDEX_BUCKET, FLAG_INDEX_KEY)
	}
	if fv.IndexUrl != "" && (fv.IndexBucket != "" || fv.IndexKey != "") {
		return fmt.Errorf("--%s cannot be used with --%s or --%s", FLAG_INDEX_URL, FLAG_INDEX_BUCKET, FLAG_INDEX_KEY)
	}
	if fv.IndexUrl == "" && (fv.IndexBucket == "" || fv.IndexKey == "" || fv.AwsRegion == "") {
		return fmt.Errorf("--%s, --%s, and --%s must be used together", FLAG_INDEX_BUCKET, FLAG_INDEX_KEY, FLAG_AWS_REGION)
	}
	return nil
}

func ValidateKeySha1(fv *flagValues) error {
	return keyutils.ValidateFingerprintSha1(fv.Key)
}

func (v *flagValues) ValidateDecimal(flag, text string) error {
	for i, w := 0, 0; i < len(text); i += w {
		runeVal, width := utf8.DecodeRuneInString(text[i:])
		if !unicode.IsDigit(runeVal) {
			return fmt.Errorf("--%s contains non-decimal rune `%c`", flag, runeVal)
		}
		w = width
	}
	return nil
}

type CmdFunc func(flagValues *flagValues, logger kslog.KsLogger)

func cmdInitDb(flagValues *flagValues, logger kslog.KsLogger) {
	config, err := GetConfig(flagValues, logger)
	if err != nil {
		logger.Errorf("Failed to get configuration: %s", err)
		os.Exit(1)
	}
	store, err := MakeStore(config, nil)
	if err != nil {
		logger.Errorf("Failed to make store: %s", err)
		os.Exit(1)
	}
	err = store.InitDb(logger)
	if err != nil {
		logger.Errorf("Failed to initialize new database: %s", err)
		os.Exit(1)
	}
}

func cmdInitConfig(flagValues *flagValues, logger kslog.KsLogger) {
	config := appkeypb.AppKeyManagerConfig{
		DbLoc: &appkeypb.Location{},
	}
	if flagValues.IndexUrl != "" {
		config.DbLoc.Location = &appkeypb.Location_Url{
			Url: flagValues.IndexUrl,
		}
	} else {
		config.DbLoc.Location = &appkeypb.Location_S3{
			S3: &appkeypb.S3Ref{
				Bucket: flagValues.IndexBucket,
				Key:    flagValues.IndexKey,
				Region: flagValues.AwsRegion,
			},
		}
	}
	configPath, err := expandPath(flagValues.ConfigPath)
	if err != nil {
		logger.Errorf("Unable to expand path %s: %s", flagValues.ConfigPath, err)
		os.Exit(1)
	}
	configDir := filepath.Dir(configPath)
	err = os.MkdirAll(configDir, 0750)
	if err != nil {
		logger.Errorf("Unable to create directory %s: %s", configDir, err)
		os.Exit(1)
	}
	configFile, err := os.Create(configPath)
	defer configFile.Close()
	if err != nil {
		logger.Errorf("Unable to create configuration file %s: %s", configPath, err)
		os.Exit(1)
	}
	marshaler := jsonpb.Marshaler{
		Indent: "   ",
	}
	err = marshaler.Marshal(configFile, &config)
	if err != nil {
		logger.Errorf("Unable to marshal configuration: %s", err)
		os.Exit(1)
	}
	_, err = configFile.Write([]byte("\n"))
	if err != nil {
		logger.Errorf("Unable to write to configuration file: %s", err)
		os.Exit(1)
	}
}

func cmdListApps(flagValues *flagValues, logger kslog.KsLogger) {
	config, err := GetConfig(flagValues, logger)
	if err != nil {
		logger.Errorf("Failed to get configuration: %s", err)
		os.Exit(1)
	}
	store, err := MakeStore(config, nil)
	if err != nil {
		logger.Errorf("Failed to make store: %s", err)
		os.Exit(1)
	}
	req := appkeypb.ListAppsRequest{}
	index, err := store.ListApps(&req, logger)
	if err != nil {
		logger.Errorf("Failed go get app index: %s", err)
		os.Exit(1)
	}
	if err != nil {
		logger.Errorf("Failed to put application index")
		os.Exit(1)
	}
	if len(index.AppRefs) == 0 {
		logger.Logf("No apps")
	} else {
		for appId := range index.AppRefs {
			logger.Logf("app %d", appId)
		}
	}
}

func cmdAddApp(flagValues *flagValues, logger kslog.KsLogger) {
	config, err := GetConfig(flagValues, logger)
	if err != nil {
		logger.Errorf("Failed to get configuration: %s", err)
		os.Exit(1)
	}
	store, err := MakeStore(config, nil)
	if err != nil {
		logger.Errorf("Failed to make store: %s", err)
		os.Exit(1)
	}
	req := appkeypb.AddAppRequest{
		App: flagValues.App,
	}
	_, err = store.AddApp(&req, logger)
	if err != nil {
		logger.Errorf("Failed to create application %d: %s", flagValues.App, err)
		os.Exit(1)
	}
}

func cmdAddKey(flagValues *flagValues, logger kslog.KsLogger) {
	config, err := GetConfig(flagValues, logger)
	if err != nil {
		logger.Errorf("Failed to get configuration: %s", err)
		os.Exit(1)
	}
	store, err := MakeStore(config, nil)
	if err != nil {
		logger.Errorf("Failed to make store: %s", err)
		os.Exit(1)
	}
	keyFile, err := os.Open(flagValues.KeyFile)
	if err != nil {
		logger.Errorf("Failed to open key file %s", flagValues.KeyFile)
		os.Exit(1)
	}
	keyBytes, err := ioutil.ReadAll(keyFile)
	if err != nil {
		logger.Errorf("Failed to read key file %s: %s", flagValues.KeyFile, err)
		os.Exit(1)
	}
	key, err := keyutils.ParsePrivateKey(keyBytes)
	if err != nil {
		logger.Errorf("Failed to parse private key %s: %s", flagValues.KeyFile, err)
		os.Exit(1)
	}
	fingerprint, err := keyutils.KeyFingerprint(key)
	if err != nil {
		logger.Errorf("Failed to calculate key fingerprint: %s", err)
		os.Exit(1)
	}
	logger.Logf("Key has fingerprint %s", fingerprint)
	req := appkeypb.AddKeyRequest{
		App: flagValues.App,
		Keys: []*appkeypb.AppKey{
			&appkeypb.AppKey{
				Meta: &appkeypb.AppKeyMeta{
					App:         flagValues.App,
					Fingerprint: fingerprint,
				},
				Key: keyBytes,
			},
		},
	}
	_, err = store.AddKey(&req, logger)
	if err != nil {
		logger.Errorf("Failed to add key: %s", err)
		os.Exit(1)
	}
}

func cmdListKeys(flagValues *flagValues, logger kslog.KsLogger) {
	config, err := GetConfig(flagValues, logger)
	if err != nil {
		logger.Errorf("Failed to get configuration: %s", err)
		os.Exit(1)
	}
	store, err := MakeStore(config, nil)
	if err != nil {
		logger.Errorf("Failed to make store: %s", err)
		os.Exit(1)
	}
	req := appkeypb.GetAppRequest{
		App: flagValues.App,
	}
	app, err := store.GetApp(&req, logger)
	if err != nil {
		logger.Errorf("Failed to get app %d: %s", flagValues.App, err)
		os.Exit(1)
	}
	if len(app.Keys) == 0 {
		logger.Logf("App has no keys")
		return
	}
	for _, key := range app.Keys {
		logger.Logf("key %s", key.Meta.Fingerprint)
	}
}

func cmdRemoveKey(flagValues *flagValues, logger kslog.KsLogger) {
	config, err := GetConfig(flagValues, logger)
	if err != nil {
		logger.Errorf("Failed to get configuration: %s", err)
		os.Exit(1)
	}
	store, err := MakeStore(config, nil)
	if err != nil {
		logger.Errorf("Failed to make store: %s", err)
		os.Exit(1)
	}
	req := appkeypb.RemoveKeyRequest{
		App:          flagValues.App,
		Fingerprints: []string{flagValues.Key},
	}
	_, err = store.RemoveKey(&req, logger)
	if err != nil {
		logger.Errorf("Failed to remove key: %s", err)
		os.Exit(1)
	}
}

func cmdRemoveApp(flagValues *flagValues, logger kslog.KsLogger) {
	config, err := GetConfig(flagValues, logger)
	if err != nil {
		logger.Errorf("Failed to get configuration: %s", err)
		os.Exit(1)
	}
	store, err := MakeStore(config, nil)
	if err != nil {
		logger.Errorf("Failed to make store: %s", err)
		os.Exit(1)
	}
	req := appkeypb.RemoveAppRequest{
		App: flagValues.App,
	}
	_, err = store.RemoveApp(&req, logger)
	if err != nil {
		logger.Errorf("Failed to remove application %d", flagValues.App)
		os.Exit(1)
	}
	logger.Logf("Applicatoin %d removed", flagValues.App)
}

type CmdSpec struct {
	Flags         *flag.FlagSet
	RequiredFlags []string
	CheckFlags    CheckFlagsFunc
	CmdFunc       func(flagValues *flagValues, logger kslog.KsLogger)
}

func SetupFlags(flags *flagValues) map[string]CmdSpec {
	cmdSpecs := make(map[string]CmdSpec)
	flag.Usage = func() {
		output := flag.CommandLine.Output()
		fmt.Fprintf(output, "Usage of %s\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(output, "Sub-commands:\n")
		for cmdname := range cmdSpecs {
			fmt.Fprintf(output, "  %s\n", cmdname)
		}
	}
	flag.StringVar(&flags.ConfigPath, FLAG_CONFIG, USER_CONFIG_PATH, "Configuration file path")
	initDbFlags := flag.NewFlagSet(CMD_INIT_DB, flag.ExitOnError)
	cmdSpecs[CMD_INIT_DB] = CmdSpec{
		Flags:         initDbFlags,
		RequiredFlags: []string{FLAG_CONFIG},
		CmdFunc:       cmdInitDb,
	}
	initConfigFlags := flag.NewFlagSet(CMD_INIT_CONFIG, flag.ExitOnError)
	initConfigFlags.StringVar(&flags.IndexUrl, FLAG_INDEX_URL, "", "Application index url")
	initConfigFlags.StringVar(&flags.IndexBucket, FLAG_INDEX_BUCKET, "", "Database S3 bucket")
	initConfigFlags.StringVar(&flags.IndexKey, FLAG_INDEX_KEY, "", "Database S3 prefix")
	initConfigFlags.StringVar(&flags.AwsRegion, FLAG_AWS_REGION, "", "Database S3 region")
	cmdSpecs[CMD_INIT_CONFIG] = CmdSpec{
		Flags:         initConfigFlags,
		RequiredFlags: nil,
		CheckFlags:    ValidateInitConfig,
		CmdFunc:       cmdInitConfig,
	}
	listAppsFlags := flag.NewFlagSet(CMD_LIST_APPS, flag.ExitOnError)
	cmdSpecs[CMD_LIST_APPS] = CmdSpec{
		Flags:         listAppsFlags,
		RequiredFlags: []string{FLAG_CONFIG},
		CmdFunc:       cmdListApps,
	}
	addAppFlags := flag.NewFlagSet(CMD_ADD_APP, flag.ExitOnError)
	addAppFlags.Uint64Var(&flags.App, FLAG_APP, 0, "Application ID")
	cmdSpecs[CMD_ADD_APP] = CmdSpec{
		Flags:         addAppFlags,
		RequiredFlags: []string{FLAG_CONFIG, FLAG_APP},
		CmdFunc:       cmdAddApp,
	}
	addKeyFlags := flag.NewFlagSet(CMD_ADD_KEY, flag.ExitOnError)
	addKeyFlags.Uint64Var(&flags.App, FLAG_APP, 0, "Application ID")
	addKeyFlags.StringVar(&flags.KeyFile, FLAG_KEY_FILE, "", "Key file name")
	cmdSpecs[CMD_ADD_KEY] = CmdSpec{
		Flags:         addKeyFlags,
		RequiredFlags: []string{FLAG_CONFIG, FLAG_APP, FLAG_KEY_FILE},
		CmdFunc:       cmdAddKey,
	}
	listKeysFlags := flag.NewFlagSet(CMD_LIST_KEYS, flag.ExitOnError)
	listKeysFlags.Uint64Var(&flags.App, FLAG_APP, 0, "Application ID")
	cmdSpecs[CMD_LIST_KEYS] = CmdSpec{
		Flags:         listKeysFlags,
		RequiredFlags: []string{FLAG_CONFIG, FLAG_APP},
		CmdFunc:       cmdListKeys,
	}
	removeKeyFlags := flag.NewFlagSet(CMD_REM_KEY, flag.ExitOnError)
	removeKeyFlags.Uint64Var(&flags.App, FLAG_APP, 0, "Application ID")
	removeKeyFlags.StringVar(&flags.Key, FLAG_KEY, "", "Key fingerprint")
	cmdSpecs[CMD_REM_KEY] = CmdSpec{
		Flags:         removeKeyFlags,
		RequiredFlags: []string{FLAG_CONFIG, FLAG_APP, FLAG_KEY},
		CheckFlags:    ValidateKeySha1,
		CmdFunc:       cmdRemoveKey,
	}
	remAppFlags := flag.NewFlagSet(CMD_REM_APP, flag.ExitOnError)
	remAppFlags.Uint64Var(&flags.App, FLAG_APP, 0, "Application ID")
	cmdSpecs[CMD_REM_APP] = CmdSpec{
		Flags:         remAppFlags,
		RequiredFlags: []string{FLAG_CONFIG, FLAG_APP},
		CmdFunc:       cmdRemoveApp,
	}
	return cmdSpecs
}

func main() {
	var flagValues flagValues
	cmdSpecs := SetupFlags(&flagValues)
	flag.Parse()
	subArgs := flag.Args()
	if len(subArgs) == 0 {
		fmt.Fprintln(os.Stderr, "A subcommand is required")
		flag.Usage()
		os.Exit(2)
	}
	cmdSpec := cmdSpecs[subArgs[0]]
	err := cmdSpec.Flags.Parse(subArgs[1:])
	if err == nil {
		err = flagValues.Require(cmdSpec.RequiredFlags...)
	}
	if err == nil && cmdSpec.CheckFlags != nil {
		err = cmdSpec.CheckFlags(&flagValues)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		cmdSpec.Flags.PrintDefaults()
		os.Exit(2)
	}
	logger := kslog.DefaultLogger{}
	logger.Logf("Using configuration file %s", flagValues.ConfigPath)
	cmdSpec.CmdFunc(&flagValues, logger)
}
