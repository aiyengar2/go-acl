//go:build windows

package acl

import (
	"github.com/hectane/go-acl/api"
	"golang.org/x/sys/windows"
)

func isBuiltinAdministrator() (bool, error) {
	var (
		sid    windows.SID
		sidLen = uint32(api.SECURITY_MAX_SID_SIZE)
	)
	err := api.CreateWellKnownSid(
		api.WinBuiltinAdministratorsSid,
		nil,
		&sid,
		&sidLen,
	)
	if err != nil {
		return false, err
	}

	var tokenHandle windows.Handle
	return api.CheckTokenMembership(tokenHandle, &sid)
}
