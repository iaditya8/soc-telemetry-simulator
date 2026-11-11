package formatter

import (
	"math/rand"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/iaditya8/soc-telemetry-simulator/pkg/buffer"
	"github.com/iaditya8/soc-telemetry-simulator/pkg/fleet"
)

func sampleLinuxEndpoint() *fleet.Endpoint {
	return &fleet.Endpoint{
		ID:         "EP-LNX-SRV-0001",
		Hostname:   "srv-prod-app01",
		Domain:     "corp.local",
		IP:         net.ParseIP("10.200.10.15"),
		IPStr:      "10.200.10.15",
		Role:       fleet.RoleLinuxServer,
		OSFamily:   "Linux",
		OSVersion:  "Ubuntu 22.04 LTS",
		Department: "IT Operations",
		ActiveUsers: []fleet.ActiveUser{
			{
				Username: "sysadmin",
				Domain:   "corp.local",
				UserSID:  "1000",
				LogonID:  "pts/0",
			},
		},
	}
}

func TestLinuxSSHAuthRFC3164(t *testing.T) {
	formatter := NewLinuxSyslogFormatter()
	ep := sampleLinuxEndpoint()
	now := time.Date(2026, 11, 12, 4, 30, 0, 0, time.UTC)

	// 1. Success with publickey
	buf := buffer.GetBuffer()
	formatter.FormatSSHAuth(buf, ep, SSHAuthParams{
		Success:    true,
		Method:     "publickey",
		ClientIP:   "10.100.1.25",
		ClientPort: 54321,
		PID:        14205,
	}, SyslogFormatRFC3164, now)

	line := buf.String()
	buf.Release()

	expectedSub := "<86>Nov 12 04:30:00 srv-prod-app01 sshd[14205]: Accepted publickey for sysadmin from 10.100.1.25 port 54321 ssh2: RSA SHA256"
	if !strings.HasPrefix(line, expectedSub) {
		t.Fatalf("expected prefix:\n%s\ngot:\n%s", expectedSub, line)
	}

	// 2. Failure with invalid user
	buf = buffer.GetBuffer()
	formatter.FormatSSHAuth(buf, ep, SSHAuthParams{
		Username:      "attacker",
		IsInvalidUser: true,
		Success:       false,
		Method:        "password",
		ClientIP:      "192.168.1.100",
		ClientPort:    44123,
		PID:           14206,
	}, SyslogFormatRFC3164, now)

	line = buf.String()
	buf.Release()

	expectedSub = "<85>Nov 12 04:30:00 srv-prod-app01 sshd[14206]: Failed password for invalid user attacker from 192.168.1.100 port 44123 ssh2"
	if !strings.HasPrefix(line, expectedSub) {
		t.Fatalf("expected prefix:\n%s\ngot:\n%s", expectedSub, line)
	}
}

func TestLinuxSSHAuthRFC5424(t *testing.T) {
	formatter := NewLinuxSyslogFormatter()
	ep := sampleLinuxEndpoint()
	now := time.Date(2026, 11, 12, 4, 30, 0, 123456000, time.UTC)

	buf := buffer.GetBuffer()
	formatter.FormatSSHAuth(buf, ep, SSHAuthParams{
		Success:    true,
		Method:     "password",
		ClientIP:   "10.100.1.50",
		ClientPort: 59123,
		PID:        14210,
	}, SyslogFormatRFC5424, now)

	line := buf.String()
	buf.Release()

	expectedSub := "<86>1 2026-11-12T04:30:00.123456Z srv-prod-app01 sshd 14210 AUTH [auth@41058 outcome=\"success\" method=\"password\" user=\"sysadmin\" client_ip=\"10.100.1.50\"] Accepted password for sysadmin from 10.100.1.50 port 59123 ssh2"
	if !strings.HasPrefix(line, expectedSub) {
		t.Fatalf("expected prefix:\n%s\ngot:\n%s", expectedSub, line)
	}
}

func TestLinuxSudoRFC3164(t *testing.T) {
	formatter := NewLinuxSyslogFormatter()
	ep := sampleLinuxEndpoint()
	now := time.Date(2026, 11, 12, 4, 30, 0, 0, time.UTC)

	buf := buffer.GetBuffer()
	formatter.FormatSudo(buf, ep, SudoParams{
		Username: "sysadmin",
		RunAs:    "root",
		TTY:      "pts/0",
		PWD:      "/root",
		Command:  "/usr/bin/cat /etc/shadow",
		PID:      15001,
	}, SyslogFormatRFC3164, now)

	line := buf.String()
	buf.Release()

	expected := "<85>Nov 12 04:30:00 srv-prod-app01 sudo: sysadmin : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow\n"
	if line != expected {
		t.Fatalf("expected:\n%s\ngot:\n%s", expected, line)
	}
}

func TestLinuxSudoRFC5424(t *testing.T) {
	formatter := NewLinuxSyslogFormatter()
	ep := sampleLinuxEndpoint()
	now := time.Date(2026, 11, 12, 4, 30, 0, 0, time.UTC)

	buf := buffer.GetBuffer()
	formatter.FormatSudo(buf, ep, SudoParams{
		Username: "sysadmin",
		RunAs:    "root",
		TTY:      "pts/1",
		PWD:      "/home/sysadmin",
		Command:  "/usr/bin/systemctl restart docker",
		PID:      15002,
	}, SyslogFormatRFC5424, now)

	line := buf.String()
	buf.Release()

	expectedSub := "<85>1 2026-11-12T04:30:00.000000Z srv-prod-app01 sudo 15002 COMMAND [sudo@41058 user=\"sysadmin\" runas=\"root\" tty=\"pts/1\" pwd=\"/home/sysadmin\"] sysadmin : TTY=pts/1 ; PWD=/home/sysadmin ; USER=root ; COMMAND=/usr/bin/systemctl restart docker"
	if !strings.HasPrefix(line, expectedSub) {
		t.Fatalf("expected prefix:\n%s\ngot:\n%s", expectedSub, line)
	}
}

func TestLinuxSystemd(t *testing.T) {
	formatter := NewLinuxSyslogFormatter()
	ep := sampleLinuxEndpoint()
	now := time.Date(2026, 11, 12, 4, 30, 0, 0, time.UTC)

	// RFC 3164
	buf := buffer.GetBuffer()
	formatter.FormatSystemd(buf, ep, SystemdParams{
		Unit:        "nginx.service",
		Action:      "Started",
		Description: "A high performance web server",
		PID:         1,
	}, SyslogFormatRFC3164, now)

	line := buf.String()
	buf.Release()

	expected := "<30>Nov 12 04:30:00 srv-prod-app01 systemd[1]: Started nginx.service - A high performance web server.\n"
	if line != expected {
		t.Fatalf("expected:\n%s\ngot:\n%s", expected, line)
	}

	// RFC 5424
	buf = buffer.GetBuffer()
	formatter.FormatSystemd(buf, ep, SystemdParams{
		Unit:        "docker.service",
		Action:      "Stopped",
		Description: "Docker Application Container Engine",
		PID:         1,
	}, SyslogFormatRFC5424, now)

	line = buf.String()
	buf.Release()

	expectedSub := "<30>1 2026-11-12T04:30:00.000000Z srv-prod-app01 systemd 1 UNIT_STATUS - Stopped docker.service - Docker Application Container Engine."
	if !strings.HasPrefix(line, expectedSub) {
		t.Fatalf("expected prefix:\n%s\ngot:\n%s", expectedSub, line)
	}
}

func TestFormatRandomLinuxEvent(t *testing.T) {
	formatter := NewLinuxSyslogFormatter()
	ep := sampleLinuxEndpoint()
	now := time.Now().UTC()
	rng := rand.New(rand.NewSource(99999))

	for i := 0; i < 200; i++ {
		buf := buffer.GetBuffer()
		formatter.FormatRandomLinuxEvent(buf, ep, SyslogFormatRFC3164, now, rng)
		if buf.Len() == 0 {
			t.Fatalf("expected non-empty formatted buffer")
		}
		if !strings.HasPrefix(buf.String(), "<") {
			t.Fatalf("invalid syslog line: %s", buf.String())
		}
		buf.Release()
	}
}

func BenchmarkLinuxRFC3164(b *testing.B) {
	formatter := NewLinuxSyslogFormatter()
	ep := sampleLinuxEndpoint()
	now := time.Now().UTC()
	params := SSHAuthParams{
		Success:    true,
		Method:     "publickey",
		ClientIP:   "10.100.1.25",
		ClientPort: 54321,
		PID:        14205,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := buffer.GetBuffer()
		formatter.FormatSSHAuth(buf, ep, params, SyslogFormatRFC3164, now)
		buf.Release()
	}
}

func BenchmarkLinuxRFC5424(b *testing.B) {
	formatter := NewLinuxSyslogFormatter()
	ep := sampleLinuxEndpoint()
	now := time.Now().UTC()
	params := SudoParams{
		Username: "sysadmin",
		RunAs:    "root",
		TTY:      "pts/0",
		PWD:      "/root",
		Command:  "/usr/bin/cat /etc/shadow",
		PID:      15001,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := buffer.GetBuffer()
		formatter.FormatSudo(buf, ep, params, SyslogFormatRFC5424, now)
		buf.Release()
	}
}
