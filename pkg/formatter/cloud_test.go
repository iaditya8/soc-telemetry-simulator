package formatter

import (
	"encoding/json"
	"math/rand"
	"testing"
	"time"

	"github.com/iaditya8/soc-telemetry-simulator/pkg/buffer"
	"github.com/iaditya8/soc-telemetry-simulator/pkg/fleet"
)

func TestCloudTrailJSONValidity(t *testing.T) {
	fmt := NewAWSCloudTrailFormatter()
	buf := buffer.GetBuffer()
	defer buf.Release()

	ts := time.Date(2026, 11, 12, 8, 0, 0, 0, time.UTC)
	ep := &fleet.Endpoint{
		Hostname: "cloud-gw-01",
		IPStr:    "10.200.20.15",
		ActiveUsers: []fleet.ActiveUser{
			{Username: "cloud-admin"},
		},
	}

	params := CloudTrailParams{
		EventTime:       ts,
		EventSource:     "iam.amazonaws.com",
		EventName:       "AttachUserPolicy",
		AWSRegion:       "us-east-1",
		UserName:        "cloud-admin",
		UserType:        "IAMUser",
		AccountID:       "123456789012",
		ARN:             "arn:aws:iam::123456789012:user/cloud-admin",
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SourceIPAddress: "198.51.100.50",
		UserAgent:       "aws-cli/2.15.15",
		RequestParamsJSON: `{"policyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}`,
		IsManagement:    true,
	}

	fmt.FormatRecord(buf, ep, params)

	raw := buf.Bytes()
	var parsed map[string]interface{}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("CloudTrail record is not valid JSON: %v\nRaw: %s", err, string(raw))
	}

	if parsed["eventName"] != "AttachUserPolicy" {
		t.Errorf("expected eventName 'AttachUserPolicy', got %v", parsed["eventName"])
	}
	if parsed["eventSource"] != "iam.amazonaws.com" {
		t.Errorf("expected eventSource 'iam.amazonaws.com', got %v", parsed["eventSource"])
	}
	if parsed["awsRegion"] != "us-east-1" {
		t.Errorf("expected awsRegion 'us-east-1', got %v", parsed["awsRegion"])
	}
}

func TestEntraIDJSONValidity(t *testing.T) {
	fmt := NewEntraIDFormatter()
	buf := buffer.GetBuffer()
	defer buf.Release()

	ts := time.Date(2026, 11, 12, 8, 15, 0, 0, time.UTC)
	ep := &fleet.Endpoint{
		Hostname: "dmz-proxy-01",
		IPStr:    "172.16.10.5",
	}

	params := EntraIDSignInParams{
		CreatedDateTime:         ts,
		UserDisplayName:         "Alice Smith",
		UserPrincipalName:       "asmith@corp.onmicrosoft.com",
		AppDisplayName:          "Azure Portal",
		ConditionalAccessStatus: "success",
		ErrorCode:               0,
		City:                    "Seattle",
		Country:                 "US",
		RiskLevel:               "none",
	}

	fmt.FormatSignIn(buf, ep, params)

	raw := buf.Bytes()
	var parsed map[string]interface{}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("Entra ID record is not valid JSON: %v\nRaw: %s", err, string(raw))
	}

	if parsed["userPrincipalName"] != "asmith@corp.onmicrosoft.com" {
		t.Errorf("expected UPN 'asmith@corp.onmicrosoft.com', got %v", parsed["userPrincipalName"])
	}
	if parsed["appDisplayName"] != "Azure Portal" {
		t.Errorf("expected App 'Azure Portal', got %v", parsed["appDisplayName"])
	}

	statusObj, ok := parsed["status"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing status object in Entra ID record")
	}
	if statusObj["errorCode"] != float64(0) {
		t.Errorf("expected errorCode 0, got %v", statusObj["errorCode"])
	}
}

func TestRandomCloudFormatters(t *testing.T) {
	ctFmt := NewAWSCloudTrailFormatter()
	entraFmt := NewEntraIDFormatter()
	buf := buffer.GetBuffer()
	defer buf.Release()
	rng := rand.New(rand.NewSource(42))
	ep := &fleet.Endpoint{IPStr: "10.100.1.20"}

	// Test 50 random CloudTrail logs
	for i := 0; i < 50; i++ {
		buf.Reset()
		ctFmt.FormatRandomCloudTrailEvent(buf, ep, time.Now(), rng)
		var m map[string]interface{}
		if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
			t.Fatalf("Random CloudTrail failed JSON parse on iter %d: %v", i, err)
		}
	}

	// Test 50 random Entra ID logs
	for i := 0; i < 50; i++ {
		buf.Reset()
		entraFmt.FormatRandomEntraIDEvent(buf, ep, time.Now(), rng)
		var m map[string]interface{}
		if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
			t.Fatalf("Random Entra ID failed JSON parse on iter %d: %v", i, err)
		}
	}
}

func BenchmarkAWSCloudTrail(b *testing.B) {
	fmt := NewAWSCloudTrailFormatter()
	buf := buffer.GetBuffer()
	defer buf.Release()
	ts := time.Now().UTC()
	rng := rand.New(rand.NewSource(1337))
	ep := &fleet.Endpoint{IPStr: "10.100.1.20"}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		buf.Reset()
		fmt.FormatRandomCloudTrailEvent(buf, ep, ts, rng)
	}
}

func BenchmarkMicrosoftEntraID(b *testing.B) {
	fmt := NewEntraIDFormatter()
	buf := buffer.GetBuffer()
	defer buf.Release()
	ts := time.Now().UTC()
	rng := rand.New(rand.NewSource(1337))
	ep := &fleet.Endpoint{IPStr: "10.100.1.20"}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		buf.Reset()
		fmt.FormatRandomEntraIDEvent(buf, ep, ts, rng)
	}
}

