package formatter

import (
	"math/rand"
	"time"

	"github.com/iaditya8/soc-telemetry-simulator/pkg/buffer"
	"github.com/iaditya8/soc-telemetry-simulator/pkg/fleet"
)

// CloudTrailParams contains field values for an AWS CloudTrail JSON record.
type CloudTrailParams struct {
	EventTime        time.Time
	EventSource      string // e.g. "iam.amazonaws.com", "s3.amazonaws.com", "signin.amazonaws.com"
	EventName        string // e.g. "DescribeInstances", "ConsoleLogin", "PutBucketPolicy"
	AWSRegion        string // e.g. "us-east-1", "eu-west-1"
	SourceIPAddress  string
	UserAgent        string
	UserName         string
	UserType         string // "IAMUser", "Root", "AssumedRole"
	AccountID        string
	ARN              string
	AccessKeyID      string
	RequestID        string
	EventID          string
	ErrorMessage     string
	IsReadOnly       bool
	IsManagement     bool
	RequestParamsJSON string
	ResponseElemsJSON string
}

// AWSCloudTrailFormatter synthesizes conformant AWS CloudTrail JSON audit records.
type AWSCloudTrailFormatter struct{}

// NewAWSCloudTrailFormatter constructs an AWS CloudTrail formatter.
func NewAWSCloudTrailFormatter() *AWSCloudTrailFormatter {
	return &AWSCloudTrailFormatter{}
}

// FormatRecord serializes an authentic AWS CloudTrail JSON event directly into the buffer.
func (f *AWSCloudTrailFormatter) FormatRecord(buf *buffer.ByteBuffer, ep *fleet.Endpoint, p CloudTrailParams) {
	buf.AppendString(`{"eventVersion":"1.08","userIdentity":{"type":"`)
	if p.UserType != "" {
		buf.AppendString(p.UserType)
	} else {
		buf.AppendString("IAMUser")
	}
	buf.AppendString(`","principalId":"AIDA`)
	buf.AppendString(p.UserName)
	buf.AppendString(`","arn":"`)
	if p.ARN != "" {
		buf.AppendString(p.ARN)
	} else {
		buf.AppendString("arn:aws:iam::123456789012:user/")
		buf.AppendString(p.UserName)
	}
	buf.AppendString(`","accountId":"`)
	if p.AccountID != "" {
		buf.AppendString(p.AccountID)
	} else {
		buf.AppendString("123456789012")
	}
	if p.AccessKeyID != "" {
		buf.AppendString(`","accessKeyId":"`)
		buf.AppendString(p.AccessKeyID)
	}
	buf.AppendString(`","userName":"`)
	buf.AppendString(p.UserName)
	buf.AppendString(`"},"eventTime":"`)
	buf.AppendTimeISO8601(p.EventTime)
	buf.AppendString(`","eventSource":"`)
	buf.AppendString(p.EventSource)
	buf.AppendString(`","eventName":"`)
	buf.AppendString(p.EventName)
	buf.AppendString(`","awsRegion":"`)
	if p.AWSRegion != "" {
		buf.AppendString(p.AWSRegion)
	} else {
		buf.AppendString("us-east-1")
	}
	buf.AppendString(`","sourceIPAddress":"`)
	if p.SourceIPAddress != "" {
		buf.AppendString(p.SourceIPAddress)
	} else if ep != nil && ep.IPStr != "" {
		buf.AppendString(ep.IPStr)
	} else {
		buf.AppendString("198.51.100.25")
	}
	buf.AppendString(`","userAgent":"`)
	if p.UserAgent != "" {
		buf.AppendString(p.UserAgent)
	} else {
		buf.AppendString("aws-cli/2.15.15 Python/3.11.8 Linux/5.15.0")
	}
	if p.ErrorMessage != "" {
		buf.AppendString(`","errorMessage":"`)
		buf.AppendString(p.ErrorMessage)
	}
	if p.RequestParamsJSON != "" {
		buf.AppendString(`","requestParameters":`)
		buf.AppendString(p.RequestParamsJSON)
	} else {
		buf.AppendString(`","requestParameters":null`)
	}
	if p.ResponseElemsJSON != "" {
		buf.AppendString(`,"responseElements":`)
		buf.AppendString(p.ResponseElemsJSON)
	} else {
		buf.AppendString(`,"responseElements":null`)
	}
	buf.AppendString(`,"requestID":"`)
	if p.RequestID != "" {
		buf.AppendString(p.RequestID)
	} else {
		buf.AppendString("req-a1b2c3d4e5f6")
	}
	buf.AppendString(`","eventID":"`)
	if p.EventID != "" {
		buf.AppendString(p.EventID)
	} else {
		buf.AppendString("evt-12345678-abcd-ef01-2345-6789abcdef01")
	}
	buf.AppendString(`","readOnly":`)
	if p.IsReadOnly {
		buf.AppendString("true")
	} else {
		buf.AppendString("false")
	}
	buf.AppendString(`,"eventType":"AwsApiCall","managementEvent":`)
	if p.IsManagement {
		buf.AppendString("true")
	} else {
		buf.AppendString("false")
	}
	buf.AppendString(`,"recipientAccountId":"`)
	if p.AccountID != "" {
		buf.AppendString(p.AccountID)
	} else {
		buf.AppendString("123456789012")
	}
	buf.AppendString(`","eventCategory":"Management"}`)
}

var commonCloudTrailAPIs = []struct {
	Source     string
	Name       string
	ReadOnly   bool
	Management bool
}{
	{"s3.amazonaws.com", "ListBuckets", true, true},
	{"s3.amazonaws.com", "GetObject", true, false},
	{"ec2.amazonaws.com", "DescribeInstances", true, true},
	{"ec2.amazonaws.com", "DescribeSecurityGroups", true, true},
	{"iam.amazonaws.com", "GetAccountSummary", true, true},
	{"sts.amazonaws.com", "GetCallerIdentity", true, true},
	{"lambda.amazonaws.com", "ListFunctions", true, true},
	{"signin.amazonaws.com", "ConsoleLogin", false, true},
}

// FormatRandomCloudTrailEvent synthesizes a fast, realistic benign CloudTrail record.
func (f *AWSCloudTrailFormatter) FormatRandomCloudTrailEvent(buf *buffer.ByteBuffer, ep *fleet.Endpoint, ts time.Time, rng *rand.Rand) {
	api := commonCloudTrailAPIs[rng.Intn(len(commonCloudTrailAPIs))]
	userName := "devops-engineer"
	if ep != nil && len(ep.ActiveUsers) > 0 {
		userName = ep.ActiveUsers[0].Username
	}

	regions := []string{"us-east-1", "us-west-2", "eu-central-1", "ap-southeast-1"}
	region := regions[rng.Intn(len(regions))]

	params := CloudTrailParams{
		EventTime:    ts,
		EventSource:  api.Source,
		EventName:    api.Name,
		AWSRegion:    region,
		UserName:     userName,
		UserType:     "IAMUser",
		AccountID:    "123456789012",
		AccessKeyID:  "AKIAIOSFODNN7EXAMPLE",
		IsReadOnly:   api.ReadOnly,
		IsManagement: api.Management,
	}

	if api.Name == "ConsoleLogin" {
		params.ResponseElemsJSON = `{"ConsoleLogin":"Success"}`
		params.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	}

	f.FormatRecord(buf, ep, params)
}
