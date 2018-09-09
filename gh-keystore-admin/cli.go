package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/aefalcon-redux/github-keystore-protobuf/go/appkeypb"
	"github.com/aefalcon-redux/go-github-keystore/docstore"
	"github.com/aefalcon-redux/go-github-keystore/s3docstore"
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
	docStore, err := s3docstore.NewS3DocStore(config.DbLoc)
	if err != nil {
		return nil, err
	}
	store := docstore.AppKeyStore{
		DocStore: docStore,
		Links:    *links,
	}
	return &store, nil
}

func GetConfig(flags *flagValues) (*appkeypb.AppKeyManagerConfig, error) {
	configPath, err := expandPath(flags.ConfigPath)
	if err != nil {
		log.Printf("Unable to expand path %s: %s", flags.ConfigPath, err)
		return nil, err
	}
	configFile, err := os.Open(configPath)
	if err != nil {
		log.Printf("Unable to open configuration file %s: %s", configPath, err)
		return nil, err
	}
	defer configFile.Close()
	var config appkeypb.AppKeyManagerConfig
	unmarshaler := jsonpb.Unmarshaler{}
	err = unmarshaler.Unmarshal(configFile, &config)
	if err != nil {
		log.Printf("Unable to unmarshal confguration: %s", err)
		return nil, err
	}
	return &config, nil
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

type CmdFunc func(flagValues *flagValues)

func cmdInitDb(flagValues *flagValues) {
	config, err := GetConfig(flagValues)
	if err != nil {
		log.Fatalf("Failed to get configuration: %s", err)
	}
	store, err := MakeStore(config, nil)
	if err != nil {
		log.Fatalf("Failed to make store: %s", err)
	}
	var index appkeypb.AppIndex
	_, err = store.PutAppIndex(&index)
	if err != nil {
		log.Fatalf("Failed to put application index")
	}
}

func cmdInitConfig(flagValues *flagValues) {
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
		log.Fatalf("Unable to expand path %s: %s", flagValues.ConfigPath, err)
	}
	configDir := filepath.Dir(configPath)
	err = os.MkdirAll(configDir, 0750)
	if err != nil {
		log.Fatalf("Unable to create directory %s: %s", configDir, err)
	}
	configFile, err := os.Create(configPath)
	defer configFile.Close()
	if err != nil {
		log.Fatalf("Unable to create configuration file %s: %s", configPath, err)
	}
	marshaler := jsonpb.Marshaler{
		Indent: "   ",
	}
	err = marshaler.Marshal(configFile, &config)
	if err != nil {
		log.Fatalf("Unable to marshal configuration: %s", err)
	}
	_, err = configFile.Write([]byte("\n"))
	if err != nil {
		log.Fatalf("Unable to write to configuration file: %s", err)
	}
}

func cmdListApps(flagValues *flagValues) {
	config, err := GetConfig(flagValues)
	if err != nil {
		log.Fatalf("Failed to get configuration: %s", err)
	}
	store, err := MakeStore(config, nil)
	if err != nil {
		log.Fatalf("Failed to make store: %s", err)
	}
	index, _, err := store.GetAppIndex()
	if err != nil {
		log.Fatalf("Failed to put application index")
	}
	if len(index.AppRefs) == 0 {
		log.Printf("No apps")
	} else {
		for appId := range index.AppRefs {
			log.Printf("app %d", appId)
		}
	}
}

func cmdAddApp(flagValues *flagValues) {
	config, err := GetConfig(flagValues)
	if err != nil {
		log.Fatalf("Failed to get configuration: %s", err)
	}
	store, err := MakeStore(config, nil)
	if err != nil {
		log.Fatalf("Failed to make store: %s", err)
	}
	index, _, err := store.GetAppIndex()
	if err != nil {
		log.Fatalf("Failed to get application index")
	}
	if _, found := index.AppRefs[flagValues.App]; found {
		log.Fatalf("Application %d already exists", flagValues.App)
	}
	if index.AppRefs == nil {
		index.AppRefs = make(map[uint64]*appkeypb.AppIndexEntry)
	}
	index.AppRefs[flagValues.App] = &appkeypb.AppIndexEntry{
		Id: flagValues.App,
	}
	app := appkeypb.App{
		Id: flagValues.App,
	}
	_, err = store.PutApp(&app)
	if err != nil {
		log.Fatalf("Failed to put application document: %s", err)
	}
	_, err = store.PutAppIndex(index)
	if err != nil {
		log.Fatalf("Failed to put new application index: %s", err)
	}
}

func cmdAddKey(flagValues *flagValues) {
	config, err := GetConfig(flagValues)
	if err != nil {
		log.Fatalf("Failed to get configuration: %s", err)
	}
	store, err := MakeStore(config, nil)
	if err != nil {
		log.Fatalf("Failed to make store: %s", err)
	}
	keyFile, err := os.Open(flagValues.KeyFile)
	if err != nil {
		log.Fatalf("Failed to open key file %s", flagValues.KeyFile)
	}
	keyBytes, err := ioutil.ReadAll(keyFile)
	if err != nil {
		log.Fatalf("Failed to read key file %s: %s", flagValues.KeyFile, err)
	}
	key, err := ParsePrivateKey(keyBytes)
	if err != nil {
		log.Fatalf("Failed to parse private key %s: %s", flagValues.KeyFile, err)
	}
	fingerprint, err := KeyFingerprint(key)
	if err != nil {
		log.Fatalf("Failed to calculate key fingerprint: %s", err)
	}
	log.Printf("Key has fingerprint %s", fingerprint)
	app, _, err := store.GetApp(flagValues.App)
	if err != nil {
		log.Fatalf("Failed to get app %d: %s", flagValues.App, err)
	}
	if _, found := app.Keys[fingerprint]; found {
		log.Fatalf("App %d already has key %s", flagValues.App, fingerprint)
	}
	keyMeta := &appkeypb.AppKeyMeta{
		Fingerprint: fingerprint,
		App:         flagValues.App,
	}
	if app.Keys == nil {
		app.Keys = make(map[string]*appkeypb.AppKeyIndexEntry)
	}
	app.Keys[fingerprint] = &appkeypb.AppKeyIndexEntry{
		Meta: keyMeta,
	}
	_, err = store.PutKey(flagValues.App, fingerprint, keyBytes)
	if err != nil {
		log.Fatalf("Failed to put key document: %s", err)
	}
	_, err = store.PutKeyMeta(keyMeta)
	if err != nil {
		log.Fatalf("Failed to put key metadata document: %s", err)
	}
	_, err = store.PutApp(app)
	if err != nil {
		log.Fatalf("Failed to update application document: %s", err)
	}
}

func cmdListKeys(flagValues *flagValues) {
	config, err := GetConfig(flagValues)
	if err != nil {
		log.Fatalf("Failed to get configuration: %s", err)
	}
	store, err := MakeStore(config, nil)
	if err != nil {
		log.Fatalf("Failed to make store: %s", err)
	}
	app, _, err := store.GetApp(flagValues.App)
	if err != nil {
		log.Fatalf("Failed to get app %d: %s", flagValues.App, err)
	}
	if len(app.Keys) == 0 {
		log.Printf("App has no keys")
		return
	}
	for _, key := range app.Keys {
		log.Printf("key %s", key.Meta.Fingerprint)
	}
}

func cmdRemoveKey(flagValues *flagValues) {
	config, err := GetConfig(flagValues)
	if err != nil {
		log.Fatalf("Failed to get configuration: %s", err)
	}
	store, err := MakeStore(config, nil)
	if err != nil {
		log.Fatalf("Failed to make store: %s", err)
	}
	app, _, err := store.GetApp(flagValues.App)
	if err != nil {
		log.Fatalf("Failed to get app %d: %s", flagValues.App, err)
	}
	if _, found := app.Keys[flagValues.Key]; !found {
		log.Fatalf("App %d does not have  key %s", flagValues.App, flagValues.Key)
	}
	delete(app.Keys, flagValues.Key)
	_, err = store.DeleteKey(flagValues.App, flagValues.Key)
	if err != nil {
		log.Fatalf("Failed delete key %s: %s", flagValues.Key, err)
	}
	_, err = store.DeleteKeyMeta(flagValues.App, flagValues.Key)
	if err != nil {
		log.Fatalf("Failed delete key %s metadata: %s", flagValues.Key, err)
	}
	_, err = store.PutApp(app)
	if err != nil {
		log.Fatalf("Failed to update application document: %s", err)
	}
}

func cmdRemoveApp(flagValues *flagValues) {
	config, err := GetConfig(flagValues)
	if err != nil {
		log.Fatalf("Failed to get configuration: %s", err)
	}
	store, err := MakeStore(config, nil)
	if err != nil {
		log.Fatalf("Failed to make store: %s", err)
	}
	log.Printf("Removing application %d", flagValues.App)
	index, _, err := store.GetAppIndex()
	if err != nil {
		log.Fatalf("Failed to get application index")
	}
	if _, found := index.AppRefs[flagValues.App]; !found {
		log.Printf("Application %d not in index", flagValues.App)
	} else {
		delete(index.AppRefs, flagValues.App)
		_, err = store.PutAppIndex(index)
		if err != nil {
			log.Fatalf("Failed to put updated application index")
		}
		log.Printf("Application %d removed from index", flagValues.App)
	}
	app, _, err := store.GetApp(flagValues.App)
	if err != nil {
		log.Fatalf("Failed to get app %d: %s", flagValues.App, err)
	}
	_, err = store.DeleteApp(flagValues.App)
	if err != nil {
		log.Fatalf("Failed to remove app document for %d: %s", flagValues.App, err)
	}
	log.Printf("Deleted application %d", flagValues.App)
	removeKeysOk := true
	for _, key := range app.Keys {
		_, err = store.DeleteKeyMeta(flagValues.App, key.Meta.Fingerprint)
		if err != nil {
			log.Printf("Failed to remove key %s metadata", key.Meta.Fingerprint)
			removeKeysOk = false
		} else {
			log.Printf("Deleted key %s metadata", key.Meta.Fingerprint)
		}
		_, err = store.DeleteKey(flagValues.App, key.Meta.Fingerprint)
		if err != nil {
			log.Printf("Failed to remove key %s", key.Meta.Fingerprint)
			removeKeysOk = false
		} else {
			log.Printf("Deleted key %s", key.Meta.Fingerprint)
		}
	}
	if !removeKeysOk {
		log.Fatal("Failed to remove keys")
	} else {
		log.Printf("Deleted all keys")
	}
}

func ParsePrivateKey(key []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(key)
	if block != nil && block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("PEM data of type %s is not an RSA PRIVATE KEY", block.Type)
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

type CmdSpec struct {
	Flags         *flag.FlagSet
	RequiredFlags []string
	CheckFlags    func(flagValues *flagValues) error
	CmdFunc       func(flagValues *flagValues)
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
		RequiredFlags: []string{FLAG_CONFIG, FLAG_APP, FLAG_KEY},
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
	if err != nil {
		err = flagValues.Require(cmdSpec.RequiredFlags...)
	}
	if err != nil && cmdSpec.CheckFlags != nil {
		err = cmdSpec.CheckFlags(&flagValues)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		cmdSpec.Flags.PrintDefaults()
		os.Exit(2)
	}
	log.Printf("Using configuration file %s", flagValues.ConfigPath)
	cmdSpec.CmdFunc(&flagValues)
}
