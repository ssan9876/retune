package inventory

import (
	"testing"
)

// Output in the form macOS 14 prints it.
const (
	swVers = "ProductName:\t\tmacOS\nProductVersion:\t\t14.6.1\nBuildVersion:\t\t23G93\n"
	ioreg  = `+-o J314sAP  <class IOPlatformExpertDevice, id 0x100000245, registered, matched, active, busy 0 (1 ms), retain 34>
    {
      "IOPlatformUUID" = "6F9E1C2A-3B4D-5E6F-7081-92A3B4C5D6E7"
      "IOPlatformSerialNumber" = "C02ZX1YZMD6T"
      "model" = <"MacBookPro18,3">
    }`
	bootTime  = "{ sec = 1727000000, usec = 123456 } Sun Sep 22 10:13:20 2024"
	dsclUsers = "_amavisd\n_analyticsd\ndaemon\njo\nnobody\nroot\nsam\n"
	dsclAdmin = "GroupMembership: root jo\n"
	apps      = `{"SPApplicationsDataType":[
  {"_name":"Safari","version":"17.6","obtained_from":"apple","path":"/Applications/Safari.app","lastModified":"2024-08-01T10:00:00Z"},
  {"_name":"Slack","version":"4.39.95","obtained_from":"identified_developer","path":"/Applications/Slack.app","lastModified":"2024-09-01T09:30:00Z"},
  {"_name":"Tool","version":"1.0","obtained_from":"unknown","path":"/Users/jo/Applications/Tool.app"},
  {"_name":"Chess","version":"3.18","obtained_from":"apple","path":"/System/Applications/Chess.app"}
]}`
)

func TestParseMacOS(t *testing.T) {
	if name, version, build := parseSwVers(swVers); name != "macOS" || version != "14.6.1" || build != "23G93" {
		t.Errorf("sw_vers = %q %q %q", name, version, build)
	}
	if serial, uuid := parseIORegPlatform(ioreg); serial != "C02ZX1YZMD6T" || uuid != "6F9E1C2A-3B4D-5E6F-7081-92A3B4C5D6E7" {
		t.Errorf("ioreg = %q %q", serial, uuid)
	}
	if boot := parseBootTime(bootTime); boot == nil || boot.Unix() != 1727000000 {
		t.Errorf("boot = %v", boot)
	}
	if parseBootTime("garbage") != nil {
		t.Error("garbage boot time")
	}
	for out, want := range map[string]string{
		"FileVault is On.\n":                               "on",
		"FileVault is Off.\n":                              "off",
		"FileVault is On.\nDeferred enablement appears...": "on",
		"": "unknown",
	} {
		if got := parseFileVault(out); got != want {
			t.Errorf("fdesetup %q = %s, want %s", out, got, want)
		}
	}
	for out, want := range map[string][2]bool{
		"Firewall is enabled. (State = 1)":                                         {true, true},
		"Firewall is blocking all non-essential incoming connections. (State = 2)": {true, true},
		"Firewall is disabled. (State = 0)":                                        {false, true},
		"":                                                                         {false, false},
	} {
		if enabled, known := parseFirewall(out); enabled != want[0] || known != want[1] {
			t.Errorf("firewall %q = %v %v", out, enabled, known)
		}
	}
	users := parseUsers(dsclUsers)
	if len(users) != 2 || users[0].Name != "jo" || users[1].Name != "sam" {
		t.Errorf("users = %+v", users)
	}
	if admins := parseGroupMembership(dsclAdmin); len(admins) != 2 || admins[1] != "jo" {
		t.Errorf("admins = %v", admins)
	}
	if admins := parseGroupMembership("No such key: GroupMembership"); len(admins) != 0 {
		t.Errorf("no members = %v", admins)
	}

	software, err := parseApplications([]byte(apps))
	if err != nil || len(software) != 3 {
		t.Fatalf("apps = %+v, %v", software, err)
	}
	if software[0].Name != "Safari" || software[0].Publisher != "Apple" || software[0].InstallDate != "2024-08-01" || software[0].Scope != "machine" {
		t.Errorf("safari = %+v", software[0])
	}
	if software[1].Publisher != "identified developer" || software[2].Scope != "user" || software[2].Publisher != "" {
		t.Errorf("others = %+v", software[1:])
	}
	if _, err := parseApplications([]byte("not json")); err == nil {
		t.Error("garbage apps")
	}
	fw := macFirewall(true)
	if len(fw) != 3 || !fw[0].Enabled {
		t.Errorf("firewall profiles = %+v", fw)
	}
}
