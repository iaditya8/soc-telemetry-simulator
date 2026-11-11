package formatter

import (
	"math/rand"
	"strings"
	"time"

	"github.com/iaditya8/soc-telemetry-simulator/pkg/buffer"
	"github.com/iaditya8/soc-telemetry-simulator/pkg/fleet"
)

// Pre-compiled XML tag slices for zero-allocation formatting.
const (
	xmlNamespace = "http://schemas.microsoft.com/win/2004/08/events/event"

	// Provider GUID for Microsoft-Windows-Security-Auditing
	securityAuditingGUID = "{54849625-5478-4994-A5BA-3E3B0328C30D}"

	// Event IDs
	EventIDLogonSuccess  = 4624
	EventIDLogonFailure  = 4625
	EventIDProcessCreate = 4688
	EventIDUserCreated   = 4720

	// Tasks
	TaskLogon                  = 12544
	TaskProcessCreation        = 13312
	TaskUserAccountManagement  = 13824

	// Audit Keywords
	KeywordsAuditSuccess = "0x8020000000000000"
	KeywordsAuditFailure = "0x8010000000000000"
)

// Windows4624Params holds parameters for Event ID 4624 (Logon Success).
type Windows4624Params struct {
	SubjectUserSid            string
	SubjectUserName           string
	SubjectDomainName         string
	SubjectLogonID            string
	TargetUserSid             string
	TargetUserName            string
	TargetDomainName          string
	TargetLogonID             string
	LogonType                 int // 2: Interactive, 3: Network, 10: RemoteInteractive
	LogonProcessName          string
	AuthenticationPackageName string
	WorkstationName           string
	ProcessID                 uint32
	ProcessName               string
	IPAddress                 string
	IPPort                    int
}

// Windows4625Params holds parameters for Event ID 4625 (Logon Failure).
type Windows4625Params struct {
	SubjectUserSid            string
	SubjectUserName           string
	SubjectDomainName         string
	SubjectLogonID            string
	TargetUserSid             string
	TargetUserName            string
	TargetDomainName          string
	Status                    string // e.g. 0xC000006D
	SubStatus                 string // e.g. 0xC000006A (bad password) or 0xC0000064 (unknown user)
	FailureReason             string // e.g. %%2313
	LogonType                 int
	LogonProcessName          string
	AuthenticationPackageName string
	WorkstationName           string
	ProcessID                 uint32
	ProcessName               string
	IPAddress                 string
	IPPort                    int
}

// Windows4688Params holds parameters for Event ID 4688 (Process Creation).
type Windows4688Params struct {
	SubjectUserSid     string
	SubjectUserName    string
	SubjectDomainName  string
	SubjectLogonID     string
	NewProcessID       uint32
	NewProcessName     string
	ProcessCommandLine string
	ParentProcessName  string
	TokenElevationType string // e.g. %%1936 (default), %%1937 (full), %%1938 (limited)
	MandatoryLabel     string // e.g. S-1-16-8192 (Medium), S-1-16-12288 (High)
}

// Windows4720Params holds parameters for Event ID 4720 (User Account Created).
type Windows4720Params struct {
	TargetUserName    string
	TargetDomainName  string
	TargetSid         string
	SubjectUserSid    string
	SubjectUserName   string
	SubjectDomainName string
	SubjectLogonID    string
	SamAccountName    string
	DisplayName       string
	UserPrincipalName string
}

// WindowsXMLFormatter synthesizes Microsoft Event XML Schema (2004/08) conformant events.
type WindowsXMLFormatter struct{}

// NewWindowsXMLFormatter constructs a new Windows XML formatter.
func NewWindowsXMLFormatter() *WindowsXMLFormatter {
	return &WindowsXMLFormatter{}
}

// Format4624 writes an Event ID 4624 (Logon Success) XML into the buffer.
func (f *WindowsXMLFormatter) Format4624(buf *buffer.ByteBuffer, ep *fleet.Endpoint, params Windows4624Params, recordID uint64, ts time.Time) {
	writeSystemHeader(buf, EventIDLogonSuccess, TaskLogon, KeywordsAuditSuccess, recordID, ep.Hostname, ts)

	buf.AppendString("<EventData>")
	appendDataElement(buf, "SubjectUserSid", defaultVal(params.SubjectUserSid, "S-1-5-18"))
	appendDataElement(buf, "SubjectUserName", defaultVal(params.SubjectUserName, "SYSTEM"))
	appendDataElement(buf, "SubjectDomainName", defaultVal(params.SubjectDomainName, "NT AUTHORITY"))
	appendDataElement(buf, "SubjectLogonId", defaultVal(params.SubjectLogonID, "0x3E7"))

	user := ep.PrimaryUser()
	targetSID := defaultVal(params.TargetUserSid, user.UserSID)
	targetUser := defaultVal(params.TargetUserName, user.Username)
	targetDomain := defaultVal(params.TargetDomainName, user.Domain)

	appendDataElement(buf, "TargetUserSid", targetSID)
	appendDataElement(buf, "TargetUserName", targetUser)
	appendDataElement(buf, "TargetDomainName", targetDomain)
	if params.TargetLogonID != "" {
		appendDataElement(buf, "TargetLogonId", params.TargetLogonID)
	} else {
		appendDataElementHex(buf, "TargetLogonId", ep.NextLogonID())
	}

	logonType := params.LogonType
	if logonType == 0 {
		logonType = 2 // Interactive
	}
	appendDataElementInt(buf, "LogonType", int64(logonType))

	appendDataElement(buf, "LogonProcessName", defaultVal(params.LogonProcessName, "User32"))
	appendDataElement(buf, "AuthenticationPackageName", defaultVal(params.AuthenticationPackageName, "Negotiate"))
	appendDataElement(buf, "WorkstationName", defaultVal(params.WorkstationName, ep.Hostname))
	appendDataElement(buf, "LogonGuid", "{00000000-0000-0000-0000-000000000000}")
	appendDataElement(buf, "TransmittedServices", "-")
	appendDataElement(buf, "LmPackageName", "-")
	appendDataElement(buf, "KeyLength", "0")

	procID := params.ProcessID
	if procID == 0 {
		procID = uint32(ep.NextPID())
	}
	appendDataElementHex(buf, "ProcessId", uint64(procID))
	appendDataElement(buf, "ProcessName", defaultVal(params.ProcessName, `C:\Windows\System32\winlogon.exe`))

	ip := params.IPAddress
	if ip == "" {
		if ep.IPStr != "" {
			ip = ep.IPStr
		} else {
			ip = ep.IP.String()
		}
	}
	appendDataElement(buf, "IpAddress", ip)

	port := params.IPPort
	if port == 0 {
		port = 49152 + int(procID%1000)
	}
	appendDataElementInt(buf, "IpPort", int64(port))

	buf.AppendString("</EventData></Event>\n")
}

// Format4625 writes an Event ID 4625 (Logon Failure) XML into the buffer.
func (f *WindowsXMLFormatter) Format4625(buf *buffer.ByteBuffer, ep *fleet.Endpoint, params Windows4625Params, recordID uint64, ts time.Time) {
	writeSystemHeader(buf, EventIDLogonFailure, TaskLogon, KeywordsAuditFailure, recordID, ep.Hostname, ts)

	buf.AppendString("<EventData>")
	appendDataElement(buf, "SubjectUserSid", defaultVal(params.SubjectUserSid, "S-1-5-18"))
	appendDataElement(buf, "SubjectUserName", defaultVal(params.SubjectUserName, "-"))
	appendDataElement(buf, "SubjectDomainName", defaultVal(params.SubjectDomainName, "-"))
	appendDataElement(buf, "SubjectLogonId", defaultVal(params.SubjectLogonID, "0x0"))

	appendDataElement(buf, "TargetUserSid", defaultVal(params.TargetUserSid, "S-1-0-0"))
	appendDataElement(buf, "TargetUserName", defaultVal(params.TargetUserName, "administrator"))
	appendDataElement(buf, "TargetDomainName", defaultVal(params.TargetDomainName, ep.Domain))

	appendDataElement(buf, "Status", defaultVal(params.Status, "0xC000006D"))
	appendDataElement(buf, "FailureReason", defaultVal(params.FailureReason, "%%2313"))
	appendDataElement(buf, "SubStatus", defaultVal(params.SubStatus, "0xC000006A"))

	logonType := params.LogonType
	if logonType == 0 {
		logonType = 3 // Network
	}
	appendDataElementInt(buf, "LogonType", int64(logonType))

	appendDataElement(buf, "LogonProcessName", defaultVal(params.LogonProcessName, "User32"))
	appendDataElement(buf, "AuthenticationPackageName", defaultVal(params.AuthenticationPackageName, "Negotiate"))
	appendDataElement(buf, "WorkstationName", defaultVal(params.WorkstationName, ep.Hostname))
	appendDataElement(buf, "TransmittedServices", "-")
	appendDataElement(buf, "LmPackageName", "-")
	appendDataElement(buf, "KeyLength", "0")

	procID := params.ProcessID
	if procID == 0 {
		procID = uint32(ep.NextPID())
	}
	appendDataElementHex(buf, "ProcessId", uint64(procID))
	appendDataElement(buf, "ProcessName", defaultVal(params.ProcessName, `C:\Windows\System32\winlogon.exe`))

	ip := params.IPAddress
	if ip == "" {
		ip = "192.168.1.100"
	}
	appendDataElement(buf, "IpAddress", ip)

	port := params.IPPort
	if port == 0 {
		port = 50000 + int(procID%1000)
	}
	appendDataElementInt(buf, "IpPort", int64(port))

	buf.AppendString("</EventData></Event>\n")
}

// Format4688 writes an Event ID 4688 (Process Creation) XML into the buffer.
func (f *WindowsXMLFormatter) Format4688(buf *buffer.ByteBuffer, ep *fleet.Endpoint, params Windows4688Params, recordID uint64, ts time.Time) {
	writeSystemHeader(buf, EventIDProcessCreate, TaskProcessCreation, KeywordsAuditSuccess, recordID, ep.Hostname, ts)

	user := ep.PrimaryUser()
	userSID := defaultVal(params.SubjectUserSid, user.UserSID)
	userName := defaultVal(params.SubjectUserName, user.Username)
	domain := defaultVal(params.SubjectDomainName, user.Domain)
	logonID := defaultVal(params.SubjectLogonID, user.LogonID)

	buf.AppendString("<EventData>")
	appendDataElement(buf, "SubjectUserSid", userSID)
	appendDataElement(buf, "SubjectUserName", userName)
	appendDataElement(buf, "SubjectDomainName", domain)
	appendDataElement(buf, "SubjectLogonId", defaultVal(logonID, "0x100000"))

	newPID := params.NewProcessID
	if newPID == 0 {
		newPID = uint32(ep.NextPID())
	}
	appendDataElementHex(buf, "NewProcessId", uint64(newPID))
	appendDataElement(buf, "NewProcessName", defaultVal(params.NewProcessName, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`))
	appendDataElement(buf, "TokenElevationType", defaultVal(params.TokenElevationType, "%%1936"))
	appendDataElement(buf, "ProcessCommandLine", defaultVal(params.ProcessCommandLine, `"powershell.exe" -NoProfile -Command "Get-Process"`))
	appendDataElement(buf, "ParentProcessName", defaultVal(params.ParentProcessName, `C:\Windows\explorer.exe`))
	appendDataElement(buf, "TargetUserSid", "S-1-0-0")
	appendDataElement(buf, "TargetUserName", "-")
	appendDataElement(buf, "TargetDomainName", "-")
	appendDataElement(buf, "TargetLogonId", "0x0")
	appendDataElement(buf, "MandatoryLabel", defaultVal(params.MandatoryLabel, "S-1-16-8192"))

	buf.AppendString("</EventData></Event>\n")
}

// Format4720 writes an Event ID 4720 (User Account Created) XML into the buffer.
func (f *WindowsXMLFormatter) Format4720(buf *buffer.ByteBuffer, ep *fleet.Endpoint, params Windows4720Params, recordID uint64, ts time.Time) {
	writeSystemHeader(buf, EventIDUserCreated, TaskUserAccountManagement, KeywordsAuditSuccess, recordID, ep.Hostname, ts)

	admin := ep.PrimaryUser()
	adminSID := defaultVal(params.SubjectUserSid, admin.UserSID)
	adminUser := defaultVal(params.SubjectUserName, admin.Username)
	adminDomain := defaultVal(params.SubjectDomainName, admin.Domain)

	buf.AppendString("<EventData>")
	appendDataElement(buf, "TargetUserName", defaultVal(params.TargetUserName, "contractor.temp"))
	appendDataElement(buf, "TargetDomainName", defaultVal(params.TargetDomainName, ep.Domain))
	appendDataElement(buf, "TargetSid", defaultVal(params.TargetSid, "S-1-5-21-3623811015-3361044348-30300820-1199"))
	appendDataElement(buf, "SubjectUserSid", adminSID)
	appendDataElement(buf, "SubjectUserName", adminUser)
	appendDataElement(buf, "SubjectDomainName", adminDomain)
	appendDataElement(buf, "SubjectLogonId", defaultVal(params.SubjectLogonID, "0x100010"))
	appendDataElement(buf, "PrivilegeList", "-")
	appendDataElement(buf, "SamAccountName", defaultVal(params.SamAccountName, "contractor.temp"))
	appendDataElement(buf, "DisplayName", defaultVal(params.DisplayName, "Temporary Contractor"))
	appendDataElement(buf, "UserPrincipalName", defaultVal(params.UserPrincipalName, "contractor.temp@"+strings.ToLower(ep.Domain)))

	buf.AppendString("</EventData></Event>\n")
}

// FormatRandomEvent picks a realistic Windows Security event based on standard weights.
func (f *WindowsXMLFormatter) FormatRandomEvent(buf *buffer.ByteBuffer, ep *fleet.Endpoint, recordID uint64, ts time.Time, rng *rand.Rand) {
	// Standard operational probability weights:
	// Process Creation (4688): 70%
	// Successful Logon (4624): 24%
	// Failed Logon (4625): 5%
	// Account Created (4720): 1%
	r := rng.Intn(100)
	switch {
	case r < 70:
		// Process creation with varied realistic command lines
		procs := []struct {
			name string
			cmd  string
			parent string
		}{
			{`C:\Program Files\Google\Chrome\Application\chrome.exe`, `"chrome.exe" --type=utility`, `C:\Windows\explorer.exe`},
			{`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `"powershell.exe" -NoProfile -ExecutionPolicy Bypass -Command "Get-Service"`, `C:\Windows\System32\cmd.exe`},
			{`C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE`, `"EXCEL.EXE" /automation -Embedding`, `C:\Windows\explorer.exe`},
			{`C:\Windows\System32\svchost.exe`, `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`, `C:\Windows\System32\services.exe`},
			{`C:\Windows\System32\conhost.exe`, `\??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1`, `C:\Windows\System32\cmd.exe`},
		}
		p := procs[rng.Intn(len(procs))]
		f.Format4688(buf, ep, Windows4688Params{
			NewProcessName:     p.name,
			ProcessCommandLine: p.cmd,
			ParentProcessName:  p.parent,
		}, recordID, ts)

	case r < 94:
		// Successful logon
		logonTypes := []int{2, 3, 10} // Interactive, Network, RDP
		lt := logonTypes[rng.Intn(len(logonTypes))]
		f.Format4624(buf, ep, Windows4624Params{
			LogonType: lt,
		}, recordID, ts)

	case r < 99:
		// Failed logon
		f.Format4625(buf, ep, Windows4625Params{
			LogonType: 3,
			SubStatus: "0xC000006A", // Bad password
		}, recordID, ts)

	default:
		// User creation
		f.Format4720(buf, ep, Windows4720Params{}, recordID, ts)
	}
}

// writeSystemHeader appends standard Microsoft Windows Event System tags.
func writeSystemHeader(buf *buffer.ByteBuffer, eventID int, task int, keywords string, recordID uint64, computer string, ts time.Time) {
	buf.AppendString("<Event xmlns=\"")
	buf.AppendString(xmlNamespace)
	buf.AppendString("\"><System><Provider Name=\"Microsoft-Windows-Security-Auditing\" Guid=\"")
	buf.AppendString(securityAuditingGUID)
	buf.AppendString("\"/><EventID>")
	buf.AppendInt(int64(eventID))
	buf.AppendString("</EventID><Version>2</Version><Level>0</Level><Task>")
	buf.AppendInt(int64(task))
	buf.AppendString("</Task><Opcode>0</Opcode><Keywords>")
	buf.AppendString(keywords)
	buf.AppendString("</Keywords><TimeCreated SystemTime=\"")
	buf.AppendTimeISO8601(ts)
	buf.AppendString("\"/><EventRecordID>")
	buf.AppendUint(recordID)
	buf.AppendString("</EventRecordID><Execution ProcessID=\"688\" ThreadID=\"1920\"/><Channel>Security</Channel><Computer>")
	appendXMLEscaped(buf, computer)
	buf.AppendString("</Computer><Security/></System>")
}

func appendDataElement(buf *buffer.ByteBuffer, name string, val string) {
	buf.AppendString("<Data Name=\"")
	buf.AppendString(name)
	buf.AppendString("\">")
	appendXMLEscaped(buf, val)
	buf.AppendString("</Data>")
}

func appendDataElementInt(buf *buffer.ByteBuffer, name string, val int64) {
	buf.AppendString("<Data Name=\"")
	buf.AppendString(name)
	buf.AppendString("\">")
	buf.AppendInt(val)
	buf.AppendString("</Data>")
}

func appendDataElementHex(buf *buffer.ByteBuffer, name string, val uint64) {
	buf.AppendString("<Data Name=\"")
	buf.AppendString(name)
	buf.AppendString("\">")
	buf.AppendHex(val)
	buf.AppendString("</Data>")
}

// appendXMLEscaped appends text while escaping special XML entities with zero heap allocations.
func appendXMLEscaped(buf *buffer.ByteBuffer, s string) {
	last := 0
	for i := 0; i < len(s); i++ {
		var esc string
		switch s[i] {
		case '&':
			esc = "&amp;"
		case '<':
			esc = "&lt;"
		case '>':
			esc = "&gt;"
		case '"':
			esc = "&quot;"
		case '\'':
			esc = "&apos;"
		default:
			continue
		}
		if i > last {
			buf.AppendString(s[last:i])
		}
		buf.AppendString(esc)
		last = i + 1
	}
	if last < len(s) {
		buf.AppendString(s[last:])
	}
}

func defaultVal(val, def string) string {
	if val != "" {
		return val
	}
	return def
}
