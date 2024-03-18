//go:build windows

package api

import (
	"golang.org/x/sys/windows"

	"testing"
)

func TestSIDLookup(t *testing.T) {
	testCases := []struct {
		Name string
		// Based on https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-well_known_sid_type
		WellKnownSIDType int32

		// Based on https://learn.microsoft.com/en-US/windows-server/identity/ad-ds/manage/understand-security-identifiers
		ExpectedSID string
	}{
		{
			Name:             "Creator Owner",
			WellKnownSIDType: WinCreatorOwnerSid,
			ExpectedSID:      "S-1-3-0",
		},
		{
			Name:             "Creator Group",
			WellKnownSIDType: WinCreatorGroupSid,
			ExpectedSID:      "S-1-3-1",
		},
		{
			Name:             "Everyone",
			WellKnownSIDType: WinWorldSid,
			ExpectedSID:      "S-1-1-0",
		},
		{
			Name:             "Builtin Administrators",
			WellKnownSIDType: WinBuiltinAdministratorsSid,
			ExpectedSID:      "S-1-5-32-544",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			var (
				sid    windows.SID
				sidLen = uint32(SECURITY_MAX_SID_SIZE)
			)
			err := CreateWellKnownSid(
				tc.WellKnownSIDType,
				nil,
				&sid,
				&sidLen,
			)
			if err != nil {
				t.Fatal(err)
			}
			if tc.ExpectedSID != sid.String() {
				t.Fatalf("expected sid %s, found %s", tc.ExpectedSID, sid.String())
			}
		})
	}
}
