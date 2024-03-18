//go:build windows

package api

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestGetUserName(t *testing.T) {
	c := exec.Command("whoami")
	buf := bytes.Buffer{}
	c.Stderr = os.Stderr
	c.Stdout = &buf
	if err := c.Run(); err != nil {
		t.Fatal(err)
	}
	expectedUser := strings.TrimSpace(filepath.Base(buf.String()))

	user, err := GetUserName()
	if err != nil {
		t.Fatal(err)
	}
	if user != expectedUser {
		t.Fatalf("failed to find user, expected %s, found %s", expectedUser, user)
	}
}

func TestCheckTokenMembership(t *testing.T) {
	var (
		sid    windows.SID
		sidLen = uint32(SECURITY_MAX_SID_SIZE)
	)
	err := CreateWellKnownSid(
		WinAuthenticatedUserSid,
		nil,
		&sid,
		&sidLen,
	)
	if err != nil {
		t.Fatal(err)
	}

	var (
		tokenHandle windows.Handle
	)
	isMember, err := CheckTokenMembership(tokenHandle, &sid)
	if err != nil {
		t.Fatal(err)
	}
	if !isMember {
		t.Fatalf("expected current threat to be run by an authenticated user")
	}
}
