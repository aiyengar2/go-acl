//go:build windows

package api

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	maxUserNameSize uint32 = 256

	procGetUserName          = advapi32.MustFindProc("GetUserNameW")
	procCheckTokenMembership = advapi32.MustFindProc("CheckTokenMembership")
)

// https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getusernamew
func GetUserName() (string, error) {
	size := uintptr(maxUserNameSize)
	buf := make([]uint16, size)
	ret, _, err := procGetUserName.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if ret == 0 {
		return "", err
	}
	return syscall.UTF16ToString(buf), nil
}

func CheckTokenMembership(tokenHandle windows.Handle, sidToCheck *windows.SID) (bool, error) {
	var isMember int32
	ret, _, err := procCheckTokenMembership.Call(
		uintptr(tokenHandle),
		uintptr(unsafe.Pointer(sidToCheck)),
		uintptr(unsafe.Pointer(&isMember)),
	)
	if ret == 0 {
		return false, err
	}
	return isMember != 0, nil
}
