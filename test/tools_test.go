package unit_tests

import (
	"testing"

	tools "github.com/Adversary-Informed-Defense/singe/pkg/singe/tools"
	assert "github.com/stretchr/testify/assert"
)

func TestIsJSON(t *testing.T) {
	cases := []struct {
		Name   string
		Input  string
		Output bool
	}{
		{
			Name:   "Long JSON",
			Input:  `{"Event": {"System": {"Provider": {"@Name": "Microsoft-Windows-Sysmon", "@Guid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"}, "EventID": {"@Qualifiers": "", "$": 1}, "Version": 5, "Level": 4, "Task": 1, "Opcode": 0, "Keywords": "0x8000000000000000", "TimeCreated": {"@SystemTime": "2019-05-16 01:38:19.630865"}, "EventRecordID": 18002, "Correlation": {"@ActivityID": "", "@RelatedActivityID": ""}, "Execution": {"@ProcessID": 1792, "@ThreadID": 2232}, "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "DC1.insecurebank.local", "Security": {"@UserID": "S-1-5-18"}}, "EventData": {"RuleName": "Lateral Movement - Windows Remote Management", "UtcTime": "2019-05-16 01:38:19.616", "ProcessGuid": "{dfae8213-bf0b-5cdc-0000-00105a951600}", "ProcessId": 2936, "Image": "C:\\Windows\\System32\\HOSTNAME.EXE", "FileVersion": "6.3.9600.16384 (winblue_rtm.130821-1623)", "Description": "Hostname APP", "Product": "Microsoft® Windows® Operating System", "Company": "Microsoft Corporation", "CommandLine": "\"C:\\Windows\\system32\\HOSTNAME.EXE\"", "CurrentDirectory": "C:\\Users\\administrator\\Documents\\", "User": "insecurebank\\Administrator", "LogonGuid": "{dfae8213-bead-5cdc-0000-0020afda1500}", "LogonId": "0x000000000015daaf", "TerminalSessionId": 0, "IntegrityLevel": "High", "Hashes": "SHA1=4ED8B225C9CC97DD02C9A5DFD9F733C353F83E36,MD5=74D1E6E8AC6ABCC1DE934C8C5E422B64,SHA256=CA40BB9470E8E73767F3AA43DDF51F814481167DEC6C2FAA1996C18AB2C621DB,IMPHASH=65F157041816229C2919A683CBA86F70", "ParentProcessGuid": "{dfae8213-bead-5cdc-0000-0010dddb1500}", "ParentProcessId": 3332, "ParentImage": "C:\\Windows\\System32\\wsmprovhost.exe", "ParentCommandLine": "C:\\Windows\\system32\\wsmprovhost.exe -Embedding"}, "fields": {"time": 1557985099.0, "host": "DC1.insecurebank.local", "source": "LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx"}}}`,
			Output: true,
		},
		{
			Name:   "JSON Array",
			Input:  `[{"A": 1, "B": 2, "C": 3},{"X": 1, "Y": 2, "Z": 3}]`,
			Output: true,
		},
		{
			Name:   "Empty String",
			Input:  "",
			Output: false,
		},
		{
			Name:   "Invalid JSON Array",
			Input:  `[{"A": 1, "B": 2, "C": 3}{"X": 1, "Y": 2, "Z": 3}]`,
			Output: false,
		},
		{
			Name:   "Invalid Multi-Line JSON",
			Input:  `{"A": 1, "B": 2, "C": 3},{"X": 1, "Y": 2, "Z": 3}`,
			Output: false,
		},
		{
			Name:   "A JSON That Fails?",
			Input:  `{"Event": {"System": {"Provider": {"@Name": "Microsoft-Windows-Security-Auditing", "@Guid": "{54849625-5478-4994-a5ba-3e3b0328c30d}"}, "EventID": {"@Qualifiers": "", "$": 5136}, "Version": 0, "Level": 0, "Task": 14081, "Opcode": 0, "Keywords": "0x8020000000000000", "TimeCreated": {"@SystemTime": "2019-03-25 21:28:45.022631"}, "EventRecordID": 198242588, "Correlation": {"@ActivityID": "", "@RelatedActivityID": ""}, "Execution": {"@ProcessID": 444, "@ThreadID": 896}, "Channel": "Security", "Computer": "DC1.insecurebank.local", "Security": {"@UserID": ""}}, "EventData": {"OpCorrelationID": "{2ea9670c-f0f9-4d3f-90e5-a087e8c05863}", "AppCorrelationID": "-", "SubjectUserSid": "S-1-5-21-738609754-2819869699-4189121830-1108", "SubjectUserName": "bob", "SubjectDomainName": "insecurebank", "SubjectLogonId": "0x00000000040f2719", "DSName": "insecurebank.local", "DSType": "%%14676", "ObjectDN": "DC=insecurebank,DC=local", "ObjectGUID": "{c6faf700-bfe4-452a-a766-424f84c29583}", "ObjectClass": "domainDNS", "AttributeLDAPDisplayName": "nTSecurityDescriptor", "AttributeSyntaxOID": "2.5.5.15", "AttributeValue": "O:BAG:BAD:AI(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;CR;3e0f7e18-2c7a-4c10-ba82-4d926db99a3e;;S-1-5-21-738609754-2819869699-4189121830-522)(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;S-1-5-21-738609754-2819869699-4189121830-1121)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-21-738609754-2819869699-4189121830-1121)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-21-738609754-2819869699-4189121830-498)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;DD)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-21-738609754-2819869699-4189121830-1121)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO;WP;ea1b7b93-5e48-46d5-bc6c-4df4fda78a35;bf967a86-0de6-11d0-a285-00aa003049e2;PS)(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;BA)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ae-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;e2a36dc9-ae17-47c3-b58b-be34c55ba633;;S-1-5-32-557)(OA;;RP;c7407360-20bf-11d0-a768-00aa006e0529;;RU)(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;RU)(OA;CIIO;LCRPLORC;;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIO;LCRPLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;LCRPLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;CR;05c74c5e-4deb-43b4-bd9f-86664c2a7fd5;;AU)(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;ED)(OA;;CR;ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501;;AU)(OA;;CR;280f369c-67c7-438e-ae98-1d46f3c6f541;;AU)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ae-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;AU)(OA;OICI;RPWP;3f78c3e5-f79a-46bd-a0b8-9d18116ddc79;;PS)(OA;CIIO;RPWPCR;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)(A;;CCLCSWRPWPLOCRRCWDWO;;;DA)(A;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-738609754-2819869699-4189121830-519)(A;;RPRC;;;RU)(A;CI;LC;;;RU)(A;CI;CCLCSWRPWPLOCRSDRCWDWO;;;BA)(A;;RP;;;WD)(A;;LCRPLORC;;;ED)(A;;LCRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)S:(OU;CISA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)(OU;CISA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)(AU;SA;CR;;;DU)(AU;SA;CR;;;BA)(AU;SA;WPWDWO;;;WD)", "OperationType": "%%14675"}, "fields": {"time": 1553563725.0, "host": "DC1.insecurebank.local", "source": "DACL_DCSync_Right_Powerview_ Add-DomainObjectAcl.evtx"}}}`,
			Output: true,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.Name, func(t *testing.T) {
			assert.Equal(t, testCase.Output, tools.IsJSON(testCase.Input))
		})
	}
}

func TestLoadJSON(t *testing.T) {
	t.Error("TODO")
}

func TestContains(t *testing.T) {
	cases := []struct {
		Name   string
		Slice  []string
		Str    string
		Output bool
	}{
		{
			Name:   "Basic True Contains",
			Slice:  []string{"A", "B", "C", "D"},
			Str:    "B",
			Output: true,
		},
		{
			Name:   "Basic False Contains 1",
			Slice:  []string{"A", "B", "C", "D"},
			Str:    "E",
			Output: false,
		},
		{
			Name:   "Basic False Contains 2",
			Slice:  []string{"A", "B", "C", "D"},
			Str:    "a",
			Output: false,
		},
		{
			Name:   "Empty String",
			Slice:  []string{"A", "B", "C", "D"},
			Str:    "",
			Output: false,
		},
		{
			Name:   "Empty String True Match",
			Slice:  []string{"A", "B", "", "D"},
			Str:    "",
			Output: true,
		},
		{
			Name:   "Empty Slice",
			Slice:  []string{},
			Str:    "C",
			Output: false,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.Name, func(t *testing.T) {
			assert.Equal(t, testCase.Output, tools.Contains(testCase.Slice, testCase.Str))
		})
	}
}

func TestGetMapKeys(t *testing.T) {
	cases := []struct {
		Name   string
		Input  map[string]interface{}
		Output []string
	}{
		{
			Name:   "Basic 1 Depth Map",
			Input:  map[string]interface{}{"A": 1, "B": 2, "C": 3, "D": 4},
			Output: []string{"A", "B", "C", "D"},
		},
		{
			Name:   "Empty Map",
			Input:  map[string]interface{}{},
			Output: []string{},
		},
		{
			Name:   "2 Depth Map 1",
			Input:  map[string]interface{}{"A": 1, "B": map[string]interface{}{"X": 1, "Y": 2}, "C": 3, "D": 4},
			Output: []string{"A", "B", "C", "D"},
		},
		{
			Name:   "2 Depth Map 2",
			Input:  map[string]interface{}{"A": 1, "B": 2, "C": map[string]interface{}{"X": 1, "Y": 2}, "D": 4},
			Output: []string{"A", "B", "C", "D"},
		},
		{
			Name:   "2 Depth Map 3",
			Input:  map[string]interface{}{"A": map[string]interface{}{"I": 1, "J": 2}, "B": 2, "C": map[string]interface{}{"X": 1, "Y": 2}, "D": 4},
			Output: []string{"A", "B", "C", "D"},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.Name, func(t *testing.T) {
			keys := tools.GetMapKeys(testCase.Input)
			assert.Equal(t, len(testCase.Output), len(keys))
			for _, k := range testCase.Output {
				assert.True(t, tools.Contains(keys, k))
			}
		})
	}
}

func TestMapToKey(t *testing.T) {
	t.Error("TODO")
}

func TestMapToVal(t *testing.T) {
	t.Error("TODO")
}

func TestEditRule(t *testing.T) {
	t.Error("TODO")
}
