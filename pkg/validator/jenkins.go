package validator

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/titus/pkg/types"
)

type JenkinsValidator struct {
	client  *http.Client
	timeout time.Duration
}

func NewJenkinsValidator() *JenkinsValidator {
	return &JenkinsValidator{
		timeout: 5 * time.Second,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

func (v *JenkinsValidator) Name() string { return "jenkins" }

func (v *JenkinsValidator) CanValidate(ruleID string) bool {
	return ruleID == "np.jenkins.1" || ruleID == "np.jenkins.2"
}

func (v *JenkinsValidator) Validate(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	token := v.extractToken(match)
	if token == "" {
		return types.NewValidationResult(types.StatusUndetermined, 0, "cannot validate: no token found in match"), nil
	}

	snippetCtx := v.snippetContext(match)

	jenkinsURL := extractJenkinsURL(snippetCtx)
	if jenkinsURL == "" {
		return types.NewValidationResult(types.StatusUndetermined, 0, "cannot validate: no Jenkins URL found in context"), nil
	}

	host := extractHostFromURL(jenkinsURL)
	if isLocalhost(host) {
		return types.NewValidationResult(types.StatusUndetermined, 0, "skipping localhost address — cannot validate"), nil
	}

	user := extractJenkinsUser(snippetCtx)
	if user == "" {
		return types.NewValidationResult(types.StatusUndetermined, 0, "cannot validate: no Jenkins username found in context"), nil
	}

	apiURL := strings.TrimRight(jenkinsURL, "/") + "/api/json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return types.NewValidationResult(types.StatusUndetermined, 0, fmt.Sprintf("failed to create request: %v", err)), nil
	}
	req.SetBasicAuth(user, token)

	resp, err := v.client.Do(req)
	if err != nil {
		return types.NewValidationResult(types.StatusUndetermined, 0, fmt.Sprintf("connection failed: %v", err)), nil
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode == 200:
		return types.NewValidationResult(types.StatusValid, 1.0, fmt.Sprintf("Jenkins credentials valid for %s@%s", user, jenkinsURL)), nil
	case resp.StatusCode == 401 || resp.StatusCode == 403:
		return types.NewValidationResult(types.StatusInvalid, 1.0, "Jenkins credentials rejected"), nil
	default:
		return types.NewValidationResult(types.StatusUndetermined, 0.5, fmt.Sprintf("unexpected status %d from Jenkins", resp.StatusCode)), nil
	}
}

func (v *JenkinsValidator) extractToken(match *types.Match) string {
	if len(match.Groups) > 0 {
		return string(match.Groups[0])
	}
	return ""
}

func (v *JenkinsValidator) snippetContext(match *types.Match) string {
	var b strings.Builder
	b.Write(match.Snippet.Before)
	b.Write(match.Snippet.Matching)
	b.Write(match.Snippet.After)
	return b.String()
}

var (
	jenkinsURLPattern = regexp.MustCompile(
		`(?i)(?:JENKINS_?(?:URL|HOST)?|jenkins_?(?:url|host)?)\s*[:=]\s*['"]?(https?://[^\s'"` + "`" + `]+)`,
	)
	jenkinsURLFallback = regexp.MustCompile(
		`(https?://[^\s'"` + "`" + `]*jenkins[^\s'"` + "`" + `]*)`,
	)
	jenkinsUserPattern = regexp.MustCompile(
		`(?i)(?:JENKINS_?USER(?:NAME)?|jenkins_?user(?:name)?)\s*[:=]\s*['"]?([^\s'"` + "`" + `,:]+)`,
	)
	jenkinsUserFallback = regexp.MustCompile(
		`(?i)(?:jenkins_?(?:passwd|password|token))\s*[:=].*\n.*(?:jenkins_?user(?:name)?)\s*[:=]\s*['"]?([^\s'"` + "`" + `,:]+)` +
			`|` +
			`(?i)(?:jenkins_?user(?:name)?)\s*[:=]\s*['"]?([^\s'"` + "`" + `,:]+).*\n.*(?:jenkins_?(?:passwd|password|token))`,
	)
)

func extractJenkinsURL(ctx string) string {
	if m := jenkinsURLPattern.FindStringSubmatch(ctx); len(m) > 1 {
		return strings.TrimRight(m[1], "/'\"")
	}
	if m := jenkinsURLFallback.FindStringSubmatch(ctx); len(m) > 1 {
		return strings.TrimRight(m[1], "/'\"")
	}
	return ""
}

func extractJenkinsUser(ctx string) string {
	if m := jenkinsUserPattern.FindStringSubmatch(ctx); len(m) > 1 {
		return m[1]
	}
	return ""
}

func extractHostFromURL(rawURL string) string {
	rawURL = strings.TrimPrefix(rawURL, "https://")
	rawURL = strings.TrimPrefix(rawURL, "http://")
	host := strings.SplitN(rawURL, ":", 2)[0]
	host = strings.SplitN(host, "/", 2)[0]
	return host
}
