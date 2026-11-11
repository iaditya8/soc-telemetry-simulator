package formatter

import (
	"math/rand"
	"time"

	"github.com/iaditya8/soc-telemetry-simulator/pkg/buffer"
	"github.com/iaditya8/soc-telemetry-simulator/pkg/fleet"
)

// SyslogFormat specifies the framing standard for emitted syslog lines.
type SyslogFormat int

const (
	// SyslogFormatRFC3164 produces BSD syslog lines (<PRI>Mmm dd hh:mm:ss HOST TAG: MSG).
	SyslogFormatRFC3164 SyslogFormat = iota
	// SyslogFormatRFC5424 produces IETF structured syslog lines (<PRI>1 TIMESTAMP HOST APP PID MSGID SD MSG).
	SyslogFormatRFC5424
)

// Syslog Facilities and Severities per RFC 5424 / RFC 3164.
const (
	FacilityDaemon   = 3
	FacilityAuth     = 4
	FacilityAuthPriv = 10

	SeverityErr     = 3
	SeverityWarning = 4
	SeverityNotice  = 5
	SeverityInfo    = 6
)

// Standard calculated PRI codes (Facility * 8 + Severity).
const (
	PRISSHSuccess   = FacilityAuthPriv*8 + SeverityInfo   // <86>
	PRISSHFailure   = FacilityAuthPriv*8 + SeverityNotice // <85>
	PRISudo         = FacilityAuthPriv*8 + SeverityNotice // <85>
	PRISystemdInfo  = FacilityDaemon*8 + SeverityInfo     // <30>
	PRISystemdWarn  = FacilityDaemon*8 + SeverityWarning  // <28>
)

// SSHAuthParams holds context for SSH authentication events.
type SSHAuthParams struct {
	Username       string
	IsInvalidUser  bool
	Success        bool
	Method         string // "publickey" or "password"
	ClientIP       string
	ClientPort     int
	PID            uint32
	KeyFingerprint string
}

// SudoParams holds context for sudo privilege execution logs.
type SudoParams struct {
	Username string
	RunAs    string // default: "root"
	TTY      string // e.g. "pts/0"
	PWD      string // e.g. "/root" or "/home/sysadmin"
	Command  string // e.g. "/usr/bin/cat /etc/shadow"
	PID      uint32
}

// SystemdParams holds context for systemd operational service events.
type SystemdParams struct {
	Unit        string // e.g. "nginx.service", "sshd.service"
	Action      string // "Started", "Stopped", "Reloaded"
	Description string // e.g. "A high performance web server"
	PID         uint32
}

// LinuxSyslogFormatter synthesizes high-performance RFC 3164 and RFC 5424 syslog logs.
type LinuxSyslogFormatter struct{}

// NewLinuxSyslogFormatter constructs a Linux syslog formatter.
func NewLinuxSyslogFormatter() *LinuxSyslogFormatter {
	return &LinuxSyslogFormatter{}
}

// FormatSSHAuth formats an SSH authentication event (success or failure) into the buffer.
func (f *LinuxSyslogFormatter) FormatSSHAuth(buf *buffer.ByteBuffer, ep *fleet.Endpoint, params SSHAuthParams, format SyslogFormat, ts time.Time) {
	pri := PRISSHSuccess
	if !params.Success {
		pri = PRISSHFailure
	}

	user := ep.PrimaryUser()
	userName := params.Username
	if userName == "" {
		userName = user.Username
	}

	clientIP := params.ClientIP
	if clientIP == "" {
		clientIP = "10.100.1.15"
	}

	clientPort := params.ClientPort
	if clientPort <= 0 {
		clientPort = 54822
	}

	method := params.Method
	if method == "" {
		method = "publickey"
	}

	pid := params.PID
	if pid == 0 {
		pid = ep.NextPID()
	}

	if format == SyslogFormatRFC5424 {
		// RFC 5424: <PRI>1 TIMESTAMP HOST APP-NAME PROCID MSGID [SD] MSG
		writeRFC5424Header(buf, pri, ep.Hostname, "sshd", pid, "AUTH", ts)
		buf.AppendString(" [auth@41058 outcome=\"")
		if params.Success {
			buf.AppendString("success")
		} else {
			buf.AppendString("failure")
		}
		buf.AppendString("\" method=\"")
		buf.AppendString(method)
		buf.AppendString("\" user=\"")
		buf.AppendString(userName)
		buf.AppendString("\" client_ip=\"")
		buf.AppendString(clientIP)
		buf.AppendString("\"] ")
	} else {
		// RFC 3164: <PRI>TIMESTAMP HOST sshd[PID]: MSG
		writeRFC3164Header(buf, pri, ep.Hostname, ts)
		buf.AppendString("sshd[")
		buf.AppendUint(uint64(pid))
		buf.AppendString("]: ")
	}

	if params.Success {
		buf.AppendString("Accepted ")
		buf.AppendString(method)
		buf.AppendString(" for ")
		buf.AppendString(userName)
		buf.AppendString(" from ")
		buf.AppendString(clientIP)
		buf.AppendString(" port ")
		buf.AppendInt(int64(clientPort))
		buf.AppendString(" ssh2")
		if method == "publickey" {
			buf.AppendString(": RSA SHA256:4t7Xg617B5B6x44k9Z1X2Y3Z")
		}
	} else {
		buf.AppendString("Failed password for ")
		if params.IsInvalidUser {
			buf.AppendString("invalid user ")
		}
		buf.AppendString(userName)
		buf.AppendString(" from ")
		buf.AppendString(clientIP)
		buf.AppendString(" port ")
		buf.AppendInt(int64(clientPort))
		buf.AppendString(" ssh2")
	}
	buf.AppendByte('\n')
}

// FormatSudo formats a sudo command execution log into the buffer.
func (f *LinuxSyslogFormatter) FormatSudo(buf *buffer.ByteBuffer, ep *fleet.Endpoint, params SudoParams, format SyslogFormat, ts time.Time) {
	user := ep.PrimaryUser()
	userName := params.Username
	if userName == "" {
		userName = user.Username
	}

	runAs := params.RunAs
	if runAs == "" {
		runAs = "root"
	}

	tty := params.TTY
	if tty == "" {
		tty = "pts/0"
	}

	pwd := params.PWD
	if pwd == "" {
		pwd = "/home/" + userName
	}

	cmd := params.Command
	if cmd == "" {
		cmd = "/usr/bin/systemctl restart nginx"
	}

	pid := params.PID
	if pid == 0 {
		pid = ep.NextPID()
	}

	if format == SyslogFormatRFC5424 {
		writeRFC5424Header(buf, PRISudo, ep.Hostname, "sudo", pid, "COMMAND", ts)
		buf.AppendString(" [sudo@41058 user=\"")
		buf.AppendString(userName)
		buf.AppendString("\" runas=\"")
		buf.AppendString(runAs)
		buf.AppendString("\" tty=\"")
		buf.AppendString(tty)
		buf.AppendString("\" pwd=\"")
		buf.AppendString(pwd)
		buf.AppendString("\"] ")
	} else {
		writeRFC3164Header(buf, PRISudo, ep.Hostname, ts)
		buf.AppendString("sudo: ")
	}

	buf.AppendString(userName)
	buf.AppendString(" : TTY=")
	buf.AppendString(tty)
	buf.AppendString(" ; PWD=")
	buf.AppendString(pwd)
	buf.AppendString(" ; USER=")
	buf.AppendString(runAs)
	buf.AppendString(" ; COMMAND=")
	buf.AppendString(cmd)
	buf.AppendByte('\n')
}

// FormatSystemd formats a systemd service startup or shutdown event into the buffer.
func (f *LinuxSyslogFormatter) FormatSystemd(buf *buffer.ByteBuffer, ep *fleet.Endpoint, params SystemdParams, format SyslogFormat, ts time.Time) {
	unit := params.Unit
	if unit == "" {
		unit = "nginx.service"
	}

	action := params.Action
	if action == "" {
		action = "Started"
	}

	desc := params.Description
	if desc == "" {
		desc = "A high performance web server and reverse proxy"
	}

	pid := params.PID
	if pid == 0 {
		pid = 1 // systemd PID
	}

	if format == SyslogFormatRFC5424 {
		writeRFC5424Header(buf, PRISystemdInfo, ep.Hostname, "systemd", pid, "UNIT_STATUS", ts)
		buf.AppendString(" - ") // No structured data
	} else {
		writeRFC3164Header(buf, PRISystemdInfo, ep.Hostname, ts)
		buf.AppendString("systemd[")
		buf.AppendUint(uint64(pid))
		buf.AppendString("]: ")
	}

	buf.AppendString(action)
	buf.AppendByte(' ')
	buf.AppendString(unit)
	buf.AppendString(" - ")
	buf.AppendString(desc)
	buf.AppendByte('.')
	buf.AppendByte('\n')
}

// FormatRandomLinuxEvent picks a realistic Linux syslog event based on typical enterprise weights.
func (f *LinuxSyslogFormatter) FormatRandomLinuxEvent(buf *buffer.ByteBuffer, ep *fleet.Endpoint, format SyslogFormat, ts time.Time, rng *rand.Rand) {
	// Standard operational probability weights:
	// SSH Activity: 60% (90% success, 10% failure)
	// Sudo Commands: 30%
	// Systemd lifecycle: 10%
	r := rng.Intn(100)
	switch {
	case r < 60:
		// SSH Auth
		if rng.Intn(10) == 0 {
			// Failed password
			inv := rng.Intn(2) == 0
			user := "admin"
			if inv {
				user = "testuser"
			}
			f.FormatSSHAuth(buf, ep, SSHAuthParams{
				Username:      user,
				IsInvalidUser: inv,
				Success:       false,
				Method:        "password",
				ClientIP:      "192.168.1.105",
				ClientPort:    40000 + rng.Intn(20000),
			}, format, ts)
		} else {
			// Successful publickey or password
			method := "publickey"
			if rng.Intn(3) == 0 {
				method = "password"
			}
			f.FormatSSHAuth(buf, ep, SSHAuthParams{
				Success:    true,
				Method:     method,
				ClientIP:   "10.100.1.15",
				ClientPort: 50000 + rng.Intn(15000),
			}, format, ts)
		}

	case r < 90:
		// Sudo Command Execution
		commands := []string{
			"/usr/bin/systemctl status docker",
			"/usr/bin/cat /var/log/syslog",
			"/usr/bin/tail -n 100 /var/log/nginx/access.log",
			"/usr/bin/apt update",
			"/usr/bin/systemctl reload nginx",
			"/usr/sbin/iptables -L -n",
		}
		cmd := commands[rng.Intn(len(commands))]
		f.FormatSudo(buf, ep, SudoParams{
			Command: cmd,
		}, format, ts)

	default:
		// Systemd Event
		units := []struct {
			name string
			desc string
		}{
			{"nginx.service", "A high performance web server"},
			{"cron.service", "Regular background program processing daemon"},
			{"rsyslog.service", "System Logging Service"},
			{"docker.service", "Docker Application Container Engine"},
		}
		u := units[rng.Intn(len(units))]
		f.FormatSystemd(buf, ep, SystemdParams{
			Unit:        u.name,
			Action:      "Started",
			Description: u.desc,
		}, format, ts)
	}
}

// writeRFC3164Header appends: <PRI>Mmm dd hh:mm:ss HOSTNAME
func writeRFC3164Header(buf *buffer.ByteBuffer, pri int, hostname string, ts time.Time) {
	buf.AppendByte('<')
	buf.AppendInt(int64(pri))
	buf.AppendByte('>')
	buf.AppendTimeSyslog(ts)
	buf.AppendByte(' ')
	buf.AppendString(hostname)
	buf.AppendByte(' ')
}

// writeRFC5424Header appends: <PRI>1 ISO-8601 HOSTNAME APP-NAME PROCID MSGID
func writeRFC5424Header(buf *buffer.ByteBuffer, pri int, hostname, appName string, procID uint32, msgID string, ts time.Time) {
	buf.AppendByte('<')
	buf.AppendInt(int64(pri))
	buf.AppendString(">1 ")
	buf.AppendTimeISO8601(ts)
	buf.AppendByte(' ')
	buf.AppendString(hostname)
	buf.AppendByte(' ')
	buf.AppendString(appName)
	buf.AppendByte(' ')
	buf.AppendUint(uint64(procID))
	buf.AppendByte(' ')
	if msgID != "" {
		buf.AppendString(msgID)
	} else {
		buf.AppendByte('-')
	}
}
