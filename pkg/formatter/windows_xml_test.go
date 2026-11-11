package formatter

import (
	"encoding/xml"
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/iaditya8/soc-telemetry-simulator/pkg/buffer"
	"github.com/iaditya8/soc-telemetry-simulator/pkg/fleet"
)

// WinEventEnvelope validates the XML structure via standard unmarshaling.
type WinEventEnvelope struct {
	XMLName xml.Name       `xml:"Event"`
	Xmlns   string         `xml:"xmlns,attr"`
	System  WinEventSystem `xml:"System"`
	Data    WinEventData   `xml:"EventData"`
}

type WinEventSystem struct {
	Provider struct {
		Name string `xml:"Name,attr"`
		Guid string `xml:"Guid,attr"`
	} `xml:"Provider"`
	EventID       int    `xml:"EventID"`
	Version       int    `xml:"Version"`
	Level         int    `xml:"Level"`
	Task          int    `xml:"Task"`
	Opcode        int    `xml:"Opcode"`
	Keywords      string `xml:"Keywords"`
	TimeCreated   struct {
		SystemTime string `xml:"SystemTime,attr"`
	} `xml:"TimeCreated"`
	EventRecordID uint64 `xml:"EventRecordID"`
	Execution     struct {
		ProcessID int `xml:"ProcessID,attr"`
		ThreadID  int `xml:"ThreadID,attr"`
	} `xml:"Execution"`
	Channel  string `xml:"Channel"`
	Computer string `xml:"Computer"`
}

type WinEventData struct {
	Items []WinDataElement `xml:"Data"`
}

type WinDataElement struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

func (d *WinEventData) Get(name string) string {
	for _, item := range d.Items {
		if item.Name == name {
			return item.Value
		}
	}
	return ""
}

func sampleWorkstation() *fleet.Endpoint {
	return &fleet.Endpoint{
		ID:         "EP-WIN-WKS-0001",
		Hostname:   "WKS-FIN-001.corp.local",
		Domain:     "CORP.LOCAL",
		IP:         net.ParseIP("10.100.1.10"),
		IPStr:      "10.100.1.10",
		Role:       fleet.RoleWorkstation,
		OSFamily:   "Windows",
		OSVersion:  "Windows 11 Enterprise",
		Department: "Finance",
		ActiveUsers: []fleet.ActiveUser{
			{
				Username: "alice.smith",
				Domain:   "CORP",
				UserSID:  "S-1-5-21-3623811015-3361044348-30300820-1101",
				LogonID:  "0x100010",
			},
		},
	}
}

func TestFormat4624LogonSuccess(t *testing.T) {
	fmt := NewWindowsXMLFormatter()
	buf := buffer.GetBuffer()
	defer buf.Release()

	ep := sampleWorkstation()
	now := time.Date(2026, 11, 12, 4, 30, 0, 0, time.UTC)
	fmt.Format4624(buf, ep, Windows4624Params{
		LogonType: 2,
	}, 1048576, now)

	raw := buf.Bytes()
	var evt WinEventEnvelope
	if err := xml.Unmarshal(raw, &evt); err != nil {
		t.Fatalf("XML unmarshal failed: %v\nRaw XML:\n%s", err, string(raw))
	}

	if evt.System.EventID != 4624 {
		t.Errorf("expected EventID 4624, got %d", evt.System.EventID)
	}
	if evt.System.Computer != ep.Hostname {
		t.Errorf("expected Computer %s, got %s", ep.Hostname, evt.System.Computer)
	}
	if evt.System.EventRecordID != 1048576 {
		t.Errorf("expected EventRecordID 1048576, got %d", evt.System.EventRecordID)
	}
	if evt.Data.Get("TargetUserName") != "alice.smith" {
		t.Errorf("expected TargetUserName alice.smith, got %s", evt.Data.Get("TargetUserName"))
	}
	if evt.Data.Get("LogonType") != "2" {
		t.Errorf("expected LogonType 2, got %s", evt.Data.Get("LogonType"))
	}
	if evt.Data.Get("IpAddress") != "10.100.1.10" {
		t.Errorf("expected IpAddress 10.100.1.10, got %s", evt.Data.Get("IpAddress"))
	}
}

func TestFormat4625LogonFailure(t *testing.T) {
	fmt := NewWindowsXMLFormatter()
	buf := buffer.GetBuffer()
	defer buf.Release()

	ep := sampleWorkstation()
	now := time.Now().UTC()
	fmt.Format4625(buf, ep, Windows4625Params{
		TargetUserName: "bob.malicious",
		Status:         "0xC000006D",
		SubStatus:      "0xC000006A",
		IPAddress:      "192.168.1.55",
	}, 1048577, now)

	raw := buf.Bytes()
	var evt WinEventEnvelope
	if err := xml.Unmarshal(raw, &evt); err != nil {
		t.Fatalf("XML unmarshal failed: %v\nRaw XML:\n%s", err, string(raw))
	}

	if evt.System.EventID != 4625 {
		t.Errorf("expected EventID 4625, got %d", evt.System.EventID)
	}
	if evt.System.Keywords != KeywordsAuditFailure {
		t.Errorf("expected Keywords %s, got %s", KeywordsAuditFailure, evt.System.Keywords)
	}
	if evt.Data.Get("Status") != "0xC000006D" {
		t.Errorf("expected Status 0xC000006D, got %s", evt.Data.Get("Status"))
	}
	if evt.Data.Get("SubStatus") != "0xC000006A" {
		t.Errorf("expected SubStatus 0xC000006A, got %s", evt.Data.Get("SubStatus"))
	}
	if evt.Data.Get("TargetUserName") != "bob.malicious" {
		t.Errorf("expected TargetUserName bob.malicious, got %s", evt.Data.Get("TargetUserName"))
	}
	if evt.Data.Get("IpAddress") != "192.168.1.55" {
		t.Errorf("expected IpAddress 192.168.1.55, got %s", evt.Data.Get("IpAddress"))
	}
}

func TestFormat4688ProcessCreation(t *testing.T) {
	fmt := NewWindowsXMLFormatter()
	buf := buffer.GetBuffer()
	defer buf.Release()

	ep := sampleWorkstation()
	now := time.Now().UTC()
	cmdLine := `"powershell.exe" -ExecutionPolicy Bypass -Command "Get-Process | Where-Object {$_.CPU -gt 10}"`
	fmt.Format4688(buf, ep, Windows4688Params{
		NewProcessName:     `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		ProcessCommandLine: cmdLine,
		ParentProcessName:  `C:\Windows\System32\cmd.exe`,
	}, 1048578, now)

	raw := buf.Bytes()
	var evt WinEventEnvelope
	if err := xml.Unmarshal(raw, &evt); err != nil {
		t.Fatalf("XML unmarshal failed: %v\nRaw XML:\n%s", err, string(raw))
	}

	if evt.System.EventID != 4688 {
		t.Errorf("expected EventID 4688, got %d", evt.System.EventID)
	}
	if evt.Data.Get("ProcessCommandLine") != cmdLine {
		t.Errorf("XML escaping mismatch: expected\n%s\ngot\n%s", cmdLine, evt.Data.Get("ProcessCommandLine"))
	}
	if evt.Data.Get("ParentProcessName") != `C:\Windows\System32\cmd.exe` {
		t.Errorf("expected ParentProcessName cmd.exe, got %s", evt.Data.Get("ParentProcessName"))
	}
}

func TestFormat4720UserCreated(t *testing.T) {
	fmt := NewWindowsXMLFormatter()
	buf := buffer.GetBuffer()
	defer buf.Release()

	ep := sampleWorkstation()
	now := time.Now().UTC()
	fmt.Format4720(buf, ep, Windows4720Params{
		TargetUserName: "sarah.connor",
		DisplayName:    "Sarah Connor (Contractor)",
	}, 1048579, now)

	raw := buf.Bytes()
	var evt WinEventEnvelope
	if err := xml.Unmarshal(raw, &evt); err != nil {
		t.Fatalf("XML unmarshal failed: %v\nRaw XML:\n%s", err, string(raw))
	}

	if evt.System.EventID != 4720 {
		t.Errorf("expected EventID 4720, got %d", evt.System.EventID)
	}
	if evt.Data.Get("TargetUserName") != "sarah.connor" {
		t.Errorf("expected TargetUserName sarah.connor, got %s", evt.Data.Get("TargetUserName"))
	}
	if evt.Data.Get("DisplayName") != "Sarah Connor (Contractor)" {
		t.Errorf("expected DisplayName Sarah Connor (Contractor), got %s", evt.Data.Get("DisplayName"))
	}
}

func TestXMLEscapeEntities(t *testing.T) {
	buf := buffer.GetBuffer()
	defer buf.Release()

	appendXMLEscaped(buf, `<tag attr="val & 'quoted'">special</tag>`)
	got := string(buf.Bytes())
	expected := `&lt;tag attr=&quot;val &amp; &apos;quoted&apos;&quot;&gt;special&lt;/tag&gt;`
	if got != expected {
		t.Errorf("XML escape failed: expected\n%s\ngot\n%s", expected, got)
	}
}

func TestFormatRandomEvent(t *testing.T) {
	fmt := NewWindowsXMLFormatter()
	ep := sampleWorkstation()
	now := time.Now().UTC()
	rng := rand.New(rand.NewSource(12345))

	eventCount := make(map[int]int)
	for i := 0; i < 500; i++ {
		buf := buffer.GetBuffer()
		fmt.FormatRandomEvent(buf, ep, uint64(i+1), now, rng)
		var evt WinEventEnvelope
		if err := xml.Unmarshal(buf.Bytes(), &evt); err != nil {
			t.Fatalf("unmarshal error on sample %d: %v", i, err)
		}
		eventCount[evt.System.EventID]++
		buf.Release()
	}

	// Verify all 4 event IDs were generated across 500 runs
	for _, id := range []int{4624, 4625, 4688} {
		if eventCount[id] == 0 {
			t.Errorf("expected EventID %d to have non-zero occurrences, got %d", id, eventCount[id])
		}
	}
}

func BenchmarkFormat4624(b *testing.B) {
	fmt := NewWindowsXMLFormatter()
	ep := sampleWorkstation()
	now := time.Now().UTC()
	params := Windows4624Params{LogonType: 2}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := buffer.GetBuffer()
		fmt.Format4624(buf, ep, params, uint64(i), now)
		buf.Release()
	}
}

func BenchmarkFormat4688(b *testing.B) {
	fmt := NewWindowsXMLFormatter()
	ep := sampleWorkstation()
	now := time.Now().UTC()
	params := Windows4688Params{
		NewProcessName:     `C:\Windows\System32\cmd.exe`,
		ProcessCommandLine: `"cmd.exe" /c dir`,
		ParentProcessName:  `C:\Windows\explorer.exe`,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := buffer.GetBuffer()
		fmt.Format4688(buf, ep, params, uint64(i), now)
		buf.Release()
	}
}
