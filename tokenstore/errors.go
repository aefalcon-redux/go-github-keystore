package tokenstore

import (
	"fmt"
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
