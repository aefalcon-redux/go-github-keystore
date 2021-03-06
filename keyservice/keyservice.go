package keyservice

import (
	"github.com/aefalcon/github-keystore-protobuf/go/appkeypb"
	"github.com/aefalcon/go-github-keystore/kslog"
)

type ManagerService interface {
	AddApp(*appkeypb.AddAppRequest, kslog.KsLogger) (*appkeypb.AddAppResponse, error)
	RemoveApp(*appkeypb.RemoveAppRequest, kslog.KsLogger) (*appkeypb.RemoveAppResponse, error)
	GetApp(*appkeypb.GetAppRequest, kslog.KsLogger) (*appkeypb.App, error)
	ListApps(*appkeypb.ListAppsRequest, kslog.KsLogger) (*appkeypb.AppIndex, error)
	AddKey(*appkeypb.AddKeyRequest, kslog.KsLogger) (*appkeypb.AddKeyResponse, error)
	RemoveKey(*appkeypb.RemoveKeyRequest, kslog.KsLogger) (*appkeypb.RemoveKeyResponse, error)
}

type SigningService interface {
	SignJwt(*appkeypb.SignJwtRequest, kslog.KsLogger) (*appkeypb.SignJwtResponse, error)
}
