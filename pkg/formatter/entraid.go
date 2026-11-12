package formatter

import (
	"math/rand"
	"time"

	"github.com/iaditya8/soc-telemetry-simulator/pkg/buffer"
	"github.com/iaditya8/soc-telemetry-simulator/pkg/fleet"
)

// EntraIDSignInParams defines parameters for a Microsoft Entra ID sign-in audit record.
type EntraIDSignInParams struct {
	ID                      string
	CreatedDateTime         time.Time
	UserDisplayName         string
	UserPrincipalName       string
	Domain                  string // optional domain suffix (e.g. corp.onmicrosoft.com)
	UserID                  string
	AppDisplayName          string
	AppID                   string
	IPAddress               string
	ClientAppUsed           string
	ConditionalAccessStatus string // "success", "failure", "notApplied"
	ErrorCode               int
	FailureReason           string
	City                    string
	Country                 string
	RiskLevel               string // "none", "low", "medium", "high"
	RiskDetail              string // "none", "aiGpsLocationDrift", "unfamiliarFeatures"
}

// EntraIDFormatter synthesizes conformant Microsoft Entra ID (Azure AD) sign-in logs.
type EntraIDFormatter struct{}

// NewEntraIDFormatter constructs a Microsoft Entra ID formatter.
func NewEntraIDFormatter() *EntraIDFormatter {
	return &EntraIDFormatter{}
}

// FormatSignIn serializes an authentic Entra ID sign-in JSON record directly into the buffer.
func (f *EntraIDFormatter) FormatSignIn(buf *buffer.ByteBuffer, ep *fleet.Endpoint, p EntraIDSignInParams) {
	buf.AppendString(`{"id":"`)
	if p.ID != "" {
		buf.AppendString(p.ID)
	} else {
		buf.AppendString("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
	}
	buf.AppendString(`","createdDateTime":"`)
	buf.AppendTimeISO8601(p.CreatedDateTime)
	buf.AppendString(`","userDisplayName":"`)
	buf.AppendString(p.UserDisplayName)
	buf.AppendString(`","userPrincipalName":"`)
	buf.AppendString(p.UserPrincipalName)
	if p.Domain != "" {
		buf.AppendByte('@')
		buf.AppendString(p.Domain)
	}
	buf.AppendString(`","userId":"`)
	if p.UserID != "" {
		buf.AppendString(p.UserID)
	} else {
		buf.AppendString("user-guid-0000-1111-2222-333344445555")
	}
	buf.AppendString(`","appId":"`)
	if p.AppID != "" {
		buf.AppendString(p.AppID)
	} else {
		buf.AppendString("00000003-0000-0000-c000-000000000000")
	}
	buf.AppendString(`","appDisplayName":"`)
	if p.AppDisplayName != "" {
		buf.AppendString(p.AppDisplayName)
	} else {
		buf.AppendString("Microsoft 365 Exchange Online")
	}
	buf.AppendString(`","ipAddress":"`)
	if p.IPAddress != "" {
		buf.AppendString(p.IPAddress)
	} else if ep != nil && ep.IPStr != "" {
		buf.AppendString(ep.IPStr)
	} else {
		buf.AppendString("198.51.100.30")
	}
	buf.AppendString(`","clientAppUsed":"`)
	if p.ClientAppUsed != "" {
		buf.AppendString(p.ClientAppUsed)
	} else {
		buf.AppendString("Browser")
	}
	buf.AppendString(`","conditionalAccessStatus":"`)
	if p.ConditionalAccessStatus != "" {
		buf.AppendString(p.ConditionalAccessStatus)
	} else {
		buf.AppendString("success")
	}
	buf.AppendString(`","status":{"errorCode":`)
	buf.AppendInt(int64(p.ErrorCode))
	if p.FailureReason != "" {
		buf.AppendString(`,"failureReason":"`)
		buf.AppendString(p.FailureReason)
		buf.AppendByte('"')
	} else {
		buf.AppendString(`,"failureReason":null`)
	}
	buf.AppendString(`},"location":{"city":"`)
	if p.City != "" {
		buf.AppendString(p.City)
	} else {
		buf.AppendString("New York")
	}
	buf.AppendString(`","countryOrRegion":"`)
	if p.Country != "" {
		buf.AppendString(p.Country)
	} else {
		buf.AppendString("US")
	}
	buf.AppendString(`"},"riskLevelAggregated":"`)
	if p.RiskLevel != "" {
		buf.AppendString(p.RiskLevel)
	} else {
		buf.AppendString("none")
	}
	buf.AppendString(`","riskDetail":"`)
	if p.RiskDetail != "" {
		buf.AppendString(p.RiskDetail)
	} else {
		buf.AppendString("none")
	}
	buf.AppendString(`"}`)
}

var commonEntraApps = []string{
	"Microsoft 365 Portal",
	"Microsoft Teams",
	"SharePoint Online",
	"Azure Portal",
	"Outlook Mobile",
}

// FormatRandomEntraIDEvent synthesizes a fast, realistic benign Microsoft Entra ID sign-in event.
func (f *EntraIDFormatter) FormatRandomEntraIDEvent(buf *buffer.ByteBuffer, ep *fleet.Endpoint, ts time.Time, rng *rand.Rand) {
	userName := "jdoe"
	domain := "corp.onmicrosoft.com"
	if ep != nil {
		if len(ep.ActiveUsers) > 0 {
			userName = ep.ActiveUsers[0].Username
		}
		if ep.Domain != "" {
			domain = ep.Domain
		}
	}

	app := commonEntraApps[rng.Intn(len(commonEntraApps))]
	cities := []string{"New York", "Chicago", "Dallas", "Seattle", "Austin"}
	city := cities[rng.Intn(len(cities))]

	params := EntraIDSignInParams{
		CreatedDateTime:         ts,
		UserDisplayName:         userName,
		UserPrincipalName:       userName,
		Domain:                  domain,
		AppDisplayName:          app,
		ConditionalAccessStatus: "success",
		ErrorCode:               0,
		City:                    city,
		Country:                 "US",
		RiskLevel:               "none",
		RiskDetail:              "none",
	}

	f.FormatSignIn(buf, ep, params)
}
