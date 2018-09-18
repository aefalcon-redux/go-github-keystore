package tokenservice

import (
	"github.com/aefalcon/github-keystore-protobuf/go/tokenpb"
	"github.com/aefalcon/go-github-keystore/kslog"
)

type InstallTokenService interface {
	GetInstallToken(req *tokenpb.GetInstallTokenRequest, logger kslog.KsLogger) *tokenpb.GetInstallTokenResponse
}
