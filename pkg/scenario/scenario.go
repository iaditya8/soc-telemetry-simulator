package scenario

import (
	"encoding/hex"
	"math/rand"
	"sync"
	"time"

	"github.com/iaditya8/soc-telemetry-simulator/pkg/buffer"
	"github.com/iaditya8/soc-telemetry-simulator/pkg/fleet"
	"github.com/iaditya8/soc-telemetry-simulator/pkg/formatter"
)

// MITRE ATT&CK Technique identifiers.
const (
	TechniqueBruteForce             = "T1110.001" // Password Guessing
	TechniquePortScan               = "T1046"     // Network Service Discovery
	TechniqueDNSBeaconing           = "T1071.004" // Application Layer Protocol: DNS C2
	TechniqueObfuscatedCmd          = "T1059.001" // Command and Scripting Interpreter: PowerShell
	TechniqueCloudAccountCompromise = "T1078.004" // Valid Accounts: Cloud Accounts (AWS Console)
	TechniqueCloudPasswordSpray     = "T1110.003" // Password Spraying: Microsoft Entra ID
)

// Scenario represents a stateful attack sequence.
type Scenario interface {
	TechniqueID() string
	Name() string
	IsCompleted() bool
	Step(buf *buffer.ByteBuffer, now time.Time, seq uint64, rng *rand.Rand)
}

// Formatters bundles the log source formatters for scenario execution.
type Formatters struct {
	Windows    *formatter.WindowsXMLFormatter
	Linux      *formatter.LinuxSyslogFormatter
	PaloAlto   *formatter.PaloAltoFormatter
	BIND9      *formatter.BIND9Formatter
	CloudTrail *formatter.AWSCloudTrailFormatter
	EntraID    *formatter.EntraIDFormatter
}

// NewFormatters constructs a bundle of standard formatters.
func NewFormatters() *Formatters {
	return &Formatters{
		Windows:    formatter.NewWindowsXMLFormatter(),
		Linux:      formatter.NewLinuxSyslogFormatter(),
		PaloAlto:   formatter.NewPaloAltoFormatter(),
		BIND9:      formatter.NewBIND9Formatter(),
		CloudTrail: formatter.NewAWSCloudTrailFormatter(),
		EntraID:    formatter.NewEntraIDFormatter(),
	}
}

// -------------------------------------------------------------
// 1. T1110.001 - Brute Force Scenario
// -------------------------------------------------------------

// BruteForceScenario simulates multiple failed logins followed by a successful login.
type BruteForceScenario struct {
	mu             sync.Mutex
	attackerIP     string
	targetUser     string
	targetEndpoint *fleet.Endpoint
	maxAttempts    int
	currentAttempt int
	completed      bool
	formatters     *Formatters
}

// NewBruteForceScenario constructs a new T1110.001 brute force attack.
func NewBruteForceScenario(attackerIP, targetUser string, ep *fleet.Endpoint, maxAttempts int, fmts *Formatters) *BruteForceScenario {
	if maxAttempts <= 0 {
		maxAttempts = 15
	}
	return &BruteForceScenario{
		attackerIP:     attackerIP,
		targetUser:     targetUser,
		targetEndpoint: ep,
		maxAttempts:    maxAttempts,
		formatters:     fmts,
	}
}

func (s *BruteForceScenario) TechniqueID() string { return TechniqueBruteForce }
func (s *BruteForceScenario) Name() string        { return "Password Guessing (Brute Force)" }
func (s *BruteForceScenario) IsCompleted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.completed
}

func (s *BruteForceScenario) Step(buf *buffer.ByteBuffer, now time.Time, seq uint64, rng *rand.Rand) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.completed {
		return
	}

	s.currentAttempt++
	isFinalSuccess := s.currentAttempt >= s.maxAttempts

	if s.targetEndpoint.Role == fleet.RoleLinuxServer {
		// Linux SSH brute force
		if isFinalSuccess {
			s.formatters.Linux.FormatSSHAuth(buf, s.targetEndpoint, formatter.SSHAuthParams{
				Username:   s.targetUser,
				Success:    true,
				Method:     "password",
				ClientIP:   s.attackerIP,
				ClientPort: 45000 + (s.currentAttempt % 10000),
			}, formatter.SyslogFormatRFC3164, now)
			s.completed = true
		} else {
			s.formatters.Linux.FormatSSHAuth(buf, s.targetEndpoint, formatter.SSHAuthParams{
				Username:      s.targetUser,
				IsInvalidUser: false,
				Success:       false,
				Method:        "password",
				ClientIP:      s.attackerIP,
				ClientPort:    45000 + (s.currentAttempt % 10000),
			}, formatter.SyslogFormatRFC3164, now)
		}
	} else {
		// Windows Security XML brute force
		if isFinalSuccess {
			s.formatters.Windows.Format4624(buf, s.targetEndpoint, formatter.Windows4624Params{
				TargetUserName: s.targetUser,
				LogonType:      3, // Network
				IPAddress:      s.attackerIP,
				IPPort:         49152 + (s.currentAttempt % 1000),
			}, seq, now)
			s.completed = true
		} else {
			s.formatters.Windows.Format4625(buf, s.targetEndpoint, formatter.Windows4625Params{
				TargetUserName: s.targetUser,
				LogonType:      3, // Network
				Status:         "0xC000006D",
				SubStatus:      "0xC000006A", // Bad password
				IPAddress:      s.attackerIP,
				IPPort:         49152 + (s.currentAttempt % 1000),
			}, seq, now)
		}
	}
}

// -------------------------------------------------------------
// 2. T1046 - Network Service Discovery (Port Scan)
// -------------------------------------------------------------

// PortScanScenario simulates sequential drops and threat alerts across ports.
type PortScanScenario struct {
	mu             sync.Mutex
	attackerIP     string
	targetEndpoint *fleet.Endpoint
	firewallEP     *fleet.Endpoint
	ports          []int
	currentIndex   int
	completed      bool
	formatters     *Formatters
}

// NewPortScanScenario constructs a new T1046 port scanning attack.
func NewPortScanScenario(attackerIP string, targetEP, fwEP *fleet.Endpoint, fmts *Formatters) *PortScanScenario {
	scanPorts := []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
		1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 9200, 27017,
	}
	return &PortScanScenario{
		attackerIP:     attackerIP,
		targetEndpoint: targetEP,
		firewallEP:     fwEP,
		ports:          scanPorts,
		formatters:     fmts,
	}
}

func (s *PortScanScenario) TechniqueID() string { return TechniquePortScan }
func (s *PortScanScenario) Name() string        { return "Network Service Discovery (Port Scan)" }
func (s *PortScanScenario) IsCompleted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.completed
}

func (s *PortScanScenario) Step(buf *buffer.ByteBuffer, now time.Time, seq uint64, rng *rand.Rand) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.completed {
		return
	}

	targetPort := s.ports[s.currentIndex]
	s.currentIndex++

	if s.currentIndex%10 == 0 {
		// Emit Threat alert every 10 ports
		s.formatters.PaloAlto.FormatThreat(buf, s.firewallEP, formatter.PaloAltoThreatParams{
			ThreatType:      "scan",
			ThreatID:        "99999(Port Scan detected)",
			Severity:        "medium",
			SourceIP:        s.attackerIP,
			DestinationIP:   s.targetEndpoint.IPStr,
			DestinationPort: targetPort,
		}, seq, now)
	} else {
		// Emit Traffic drop
		s.formatters.PaloAlto.FormatTraffic(buf, s.firewallEP, formatter.PaloAltoTrafficParams{
			Action:          "drop",
			SourceIP:        s.attackerIP,
			DestinationIP:   s.targetEndpoint.IPStr,
			DestinationPort: targetPort,
			Application:     "incomplete",
			SourceZone:      "untrust",
			DestinationZone: "trust",
			RuleName:        "Deny-Untrusted-Inbound",
			BytesSent:       64,
			BytesReceived:   0,
			PacketsSent:     1,
			PacketsReceived: 0,
		}, seq, now)
	}

	if s.currentIndex >= len(s.ports) {
		s.completed = true
	}
}

// -------------------------------------------------------------
// 3. T1071.004 - DNS C2 Beaconing Scenario
// -------------------------------------------------------------

// DNSBeaconingScenario simulates intermittent queries for high-entropy subdomains.
type DNSBeaconingScenario struct {
	mu             sync.Mutex
	beaconDomain   string
	sourceEndpoint *fleet.Endpoint
	dnsServer      *fleet.Endpoint
	remainingCount int
	completed      bool
	formatters     *Formatters
}

// NewDNSBeaconingScenario constructs a new T1071.004 DNS C2 beaconing attack.
func NewDNSBeaconingScenario(domain string, srcEP, dnsEP *fleet.Endpoint, count int, fmts *Formatters) *DNSBeaconingScenario {
	if domain == "" {
		domain = "darkmesh-c2.cc"
	}
	if count <= 0 {
		count = 20
	}
	return &DNSBeaconingScenario{
		beaconDomain:   domain,
		sourceEndpoint: srcEP,
		dnsServer:      dnsEP,
		remainingCount: count,
		formatters:     fmts,
	}
}

func (s *DNSBeaconingScenario) TechniqueID() string { return TechniqueDNSBeaconing }
func (s *DNSBeaconingScenario) Name() string        { return "DNS C2 Beaconing" }
func (s *DNSBeaconingScenario) IsCompleted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.completed
}

func (s *DNSBeaconingScenario) Step(buf *buffer.ByteBuffer, now time.Time, seq uint64, rng *rand.Rand) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.completed {
		return
	}

	s.remainingCount--

	// Generate high-entropy 12-char hex subdomain
	var rawBytes [6]byte
	for i := range rawBytes {
		rawBytes[i] = byte(rng.Intn(256))
	}
	subdomain := hex.EncodeToString(rawBytes[:]) + "." + s.beaconDomain

	s.formatters.BIND9.FormatQuery(buf, s.dnsServer, formatter.DNSQueryParams{
		ClientIP:   s.sourceEndpoint.IPStr,
		ClientPort: 52000 + rng.Intn(10000),
		Domain:     subdomain,
		RecordType: "TXT",
		Status:     "OK",
	}, now)

	if s.remainingCount <= 0 {
		s.completed = true
	}
}

// -------------------------------------------------------------
// 4. T1059.001 - Obfuscated PowerShell Execution
// -------------------------------------------------------------

// ObfuscatedPowerShellScenario simulates encoded malicious script execution.
type ObfuscatedPowerShellScenario struct {
	mu             sync.Mutex
	targetEndpoint *fleet.Endpoint
	completed      bool
	formatters     *Formatters
}

// NewObfuscatedPowerShellScenario constructs a new T1059.001 attack.
func NewObfuscatedPowerShellScenario(ep *fleet.Endpoint, fmts *Formatters) *ObfuscatedPowerShellScenario {
	return &ObfuscatedPowerShellScenario{
		targetEndpoint: ep,
		formatters:     fmts,
	}
}

func (s *ObfuscatedPowerShellScenario) TechniqueID() string { return TechniqueObfuscatedCmd }
func (s *ObfuscatedPowerShellScenario) Name() string        { return "Obfuscated PowerShell Execution" }
func (s *ObfuscatedPowerShellScenario) IsCompleted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.completed
}

func (s *ObfuscatedPowerShellScenario) Step(buf *buffer.ByteBuffer, now time.Time, seq uint64, rng *rand.Rand) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.completed {
		return
	}

	payloads := []string{
		`"powershell.exe" -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQA...`,
		`"powershell.exe" -nop -w hidden -e aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAA...`,
		`"powershell.exe" -Command "[Reflection.Assembly]::Load([Convert]::FromBase64String('TVqQAAMAAAAEAAAA...'))"`,
	}
	cmd := payloads[rng.Intn(len(payloads))]

	s.formatters.Windows.Format4688(buf, s.targetEndpoint, formatter.Windows4688Params{
		NewProcessName:     `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		ProcessCommandLine: cmd,
		ParentProcessName:  `C:\Windows\System32\cmd.exe`,
		TokenElevationType: "%%1937", // Full elevation
		MandatoryLabel:     "S-1-16-12288", // High Mandatory Level
	}, seq, now)

	s.completed = true
}

// -------------------------------------------------------------
// 5. T1078.004 - Cloud Account Compromise (AWS CloudTrail)
// -------------------------------------------------------------

// CloudAccountCompromiseScenario simulates AWS console brute force followed by admin privilege escalation.
type CloudAccountCompromiseScenario struct {
	mu             sync.Mutex
	targetEndpoint *fleet.Endpoint
	attackerIP     string
	targetUser     string
	maxAttempts    int
	currentAttempt int
	completed      bool
	formatters     *Formatters
}

// NewCloudAccountCompromiseScenario constructs a T1078.004 cloud account attack.
func NewCloudAccountCompromiseScenario(attackerIP, targetUser string, ep *fleet.Endpoint, maxAttempts int, fmts *Formatters) *CloudAccountCompromiseScenario {
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	return &CloudAccountCompromiseScenario{
		targetEndpoint: ep,
		attackerIP:     attackerIP,
		targetUser:     targetUser,
		maxAttempts:    maxAttempts,
		formatters:     fmts,
	}
}

func (s *CloudAccountCompromiseScenario) TechniqueID() string { return TechniqueCloudAccountCompromise }
func (s *CloudAccountCompromiseScenario) Name() string        { return "Cloud Account Compromise & Privilege Escalation" }
func (s *CloudAccountCompromiseScenario) IsCompleted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.completed
}

func (s *CloudAccountCompromiseScenario) Step(buf *buffer.ByteBuffer, now time.Time, seq uint64, rng *rand.Rand) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.completed {
		return
	}

	s.currentAttempt++

	if s.currentAttempt < s.maxAttempts {
		// Failed AWS Console Login
		s.formatters.CloudTrail.FormatRecord(buf, s.targetEndpoint, formatter.CloudTrailParams{
			EventTime:         now,
			EventSource:       "signin.amazonaws.com",
			EventName:         "ConsoleLogin",
			AWSRegion:         "us-east-1",
			UserName:          s.targetUser,
			UserType:          "IAMUser",
			SourceIPAddress:   s.attackerIP,
			UserAgent:         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			ErrorMessage:      "Failed authentication",
			ResponseElemsJSON: `{"ConsoleLogin":"Failure"}`,
			IsReadOnly:        false,
			IsManagement:      true,
		})
	} else if s.currentAttempt == s.maxAttempts {
		// Successful Console Login
		s.formatters.CloudTrail.FormatRecord(buf, s.targetEndpoint, formatter.CloudTrailParams{
			EventTime:         now,
			EventSource:       "signin.amazonaws.com",
			EventName:         "ConsoleLogin",
			AWSRegion:         "us-east-1",
			UserName:          s.targetUser,
			UserType:          "IAMUser",
			SourceIPAddress:   s.attackerIP,
			UserAgent:         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			ResponseElemsJSON: `{"ConsoleLogin":"Success"}`,
			IsReadOnly:        false,
			IsManagement:      true,
		})
	} else {
		// Privilege Escalation: Attach AdministratorAccess
		s.formatters.CloudTrail.FormatRecord(buf, s.targetEndpoint, formatter.CloudTrailParams{
			EventTime:         now,
			EventSource:       "iam.amazonaws.com",
			EventName:         "AttachUserPolicy",
			AWSRegion:         "us-east-1",
			UserName:          s.targetUser,
			UserType:          "IAMUser",
			SourceIPAddress:   s.attackerIP,
			UserAgent:         "aws-cli/2.15.15",
			RequestParamsJSON: `{"policyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}`,
			IsReadOnly:        false,
			IsManagement:      true,
		})
		s.completed = true
	}
}

// -------------------------------------------------------------
// 6. T1110.003 - Cloud Password Spraying (Microsoft Entra ID)
// -------------------------------------------------------------

// CloudPasswordSprayScenario simulates high-volume credential spray against Microsoft Entra ID.
type CloudPasswordSprayScenario struct {
	mu             sync.Mutex
	targetEndpoint *fleet.Endpoint
	attackerIP     string
	domain         string
	maxAccounts    int
	currentAccount int
	completed      bool
	formatters     *Formatters
}

// NewCloudPasswordSprayScenario constructs a T1110.003 cloud password spray attack.
func NewCloudPasswordSprayScenario(attackerIP, domain string, ep *fleet.Endpoint, maxAccounts int, fmts *Formatters) *CloudPasswordSprayScenario {
	if maxAccounts <= 0 {
		maxAccounts = 10
	}
	return &CloudPasswordSprayScenario{
		targetEndpoint: ep,
		attackerIP:     attackerIP,
		domain:         domain,
		maxAccounts:    maxAccounts,
		formatters:     fmts,
	}
}

func (s *CloudPasswordSprayScenario) TechniqueID() string { return TechniqueCloudPasswordSpray }
func (s *CloudPasswordSprayScenario) Name() string        { return "Cloud Password Spraying (Microsoft Entra ID)" }
func (s *CloudPasswordSprayScenario) IsCompleted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.completed
}

func (s *CloudPasswordSprayScenario) Step(buf *buffer.ByteBuffer, now time.Time, seq uint64, rng *rand.Rand) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.completed {
		return
	}

	s.currentAccount++
	sprayUsers := []string{"admin", "helpdesk", "finance", "ceo", "hr", "payroll", "sales", "support", "billing", "devops"}
	userName := sprayUsers[s.currentAccount%len(sprayUsers)]

	s.formatters.EntraID.FormatSignIn(buf, s.targetEndpoint, formatter.EntraIDSignInParams{
		CreatedDateTime:         now,
		UserDisplayName:         userName,
		UserPrincipalName:       userName,
		Domain:                  s.domain,
		AppDisplayName:          "Azure Active Directory PowerShell",
		IPAddress:               s.attackerIP,
		ConditionalAccessStatus: "failure",
		ErrorCode:               50126,
		FailureReason:           "Invalid username or password.",
		City:                    "Amsterdam",
		Country:                 "NL",
		RiskLevel:               "high",
		RiskDetail:              "aiGpsLocationDrift",
	})

	if s.currentAccount >= s.maxAccounts {
		s.completed = true
	}
}

