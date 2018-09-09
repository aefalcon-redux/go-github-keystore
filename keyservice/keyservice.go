package keyservice

import (
	"log"

	"github.com/aefalcon-redux/github-keystore-protobuf/go/appkeypb"
)

type ManagerService interface {
	AddApp(*appkeypb.AddAppRequest, *log.Logger) (*appkeypb.AddAppResponse, error)
	RemoveApp(*appkeypb.RemoveAppRequest, *log.Logger) (*appkeypb.RemoveAppResponse, error)
	GetApp(*appkeypb.GetAppRequest, *log.Logger) (*appkeypb.App, error)
	ListAps(*appkeypb.ListAppsRequest, *log.Logger) (*appkeypb.AppIndex, error)
	AddKey(*appkeypb.AddKeyRequest, *log.Logger) (*appkeypb.AddKeyResponse, error)
	RemoveKey(*appkeypb.RemoveKeyRequest, *log.Logger) (*appkeypb.RemoveKeyResponse, error)
}

type SigningService interface {
	Sign(*appkeypb.SignRequest, *log.Logger) (*appkeypb.SignedData, error)
}
