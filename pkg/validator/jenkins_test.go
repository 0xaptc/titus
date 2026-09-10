package validator

import (
	"context"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJenkinsValidator_Name(t *testing.T) {
	v := NewJenkinsValidator()
	assert.Equal(t, "jenkins", v.Name())
}

func TestJenkinsValidator_CanValidate(t *testing.T) {
	v := NewJenkinsValidator()

	tests := []struct {
		name   string
		ruleID string
		want   bool
	}{
		{"jenkins token rule", "np.jenkins.1", true},
		{"jenkins admin password rule", "np.jenkins.2", true},
		{"other rule", "np.aws.1", false},
		{"empty rule", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, v.CanValidate(tt.ruleID))
		})
	}
}

func TestExtractJenkinsURL(t *testing.T) {
	tests := []struct {
		name    string
		ctx     string
		wantURL string
	}{
		{
			name:    "JENKINS_URL assignment",
			ctx:     "export JENKINS_URL=https://jenkins.example.com\nexport JENKINS_TOKEN=abc123",
			wantURL: "https://jenkins.example.com",
		},
		{
			name:    "jenkins_url with single quotes",
			ctx:     "jenkins_url = 'http://10.1.188.121:8080'\njenkins_passwd = 'abc'",
			wantURL: "http://10.1.188.121:8080",
		},
		{
			name:    "JENKINS variable (no _URL suffix)",
			ctx:     "export JENKINS=jenkins-cicd.apps.sno.openshiftlabs.net\nexport JENKINS_TOKEN=abc",
			wantURL: "",
		},
		{
			name:    "fallback URL with jenkins in hostname",
			ctx:     "curl -X POST 'http://jenkins.lsfusion.luxsoft.by/job/build' --user user:pass",
			wantURL: "http://jenkins.lsfusion.luxsoft.by/job/build",
		},
		{
			name:    "no URL in context",
			ctx:     "JENKINS_TOKEN=11811f784531053132519844d047186074",
			wantURL: "",
		},
		{
			name:    "JENKINS_HOST assignment",
			ctx:     "JENKINS_HOST=https://ci.example.com\nJENKINS_TOKEN=abc",
			wantURL: "https://ci.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractJenkinsURL(tt.ctx)
			assert.Equal(t, tt.wantURL, got)
		})
	}
}

func TestExtractJenkinsUser(t *testing.T) {
	tests := []struct {
		name     string
		ctx      string
		wantUser string
	}{
		{
			name:     "JENKINS_USER export",
			ctx:      "export JENKINS_USER=justin-admin\nexport JENKINS_TOKEN=abc",
			wantUser: "justin-admin",
		},
		{
			name:     "jenkins_user assignment with quotes",
			ctx:      "jenkins_user = 'root'\njenkins_passwd = 'abc'",
			wantUser: "root",
		},
		{
			name:     "JENKINS_USERNAME",
			ctx:      "JENKINS_USERNAME=deploy-bot\nJENKINS_TOKEN=abc",
			wantUser: "deploy-bot",
		},
		{
			name:     "no user in context",
			ctx:      "JENKINS_TOKEN=abc\nJENKINS_URL=https://jenkins.example.com",
			wantUser: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractJenkinsUser(tt.ctx)
			assert.Equal(t, tt.wantUser, got)
		})
	}
}

func TestExtractHostFromURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		want    string
	}{
		{"https with port", "https://jenkins.example.com:8443", "jenkins.example.com"},
		{"http without port", "http://10.1.188.121", "10.1.188.121"},
		{"https with path", "https://ci.example.com/jenkins", "ci.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, extractHostFromURL(tt.url))
		})
	}
}

func TestJenkinsValidator_MissingToken(t *testing.T) {
	v := NewJenkinsValidator()

	match := &types.Match{
		RuleID: "np.jenkins.1",
		Groups: [][]byte{},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "no token")
}

func TestJenkinsValidator_MissingURL(t *testing.T) {
	v := NewJenkinsValidator()

	match := &types.Match{
		RuleID: "np.jenkins.1",
		Groups: [][]byte{[]byte("11811f784531053132519844d047186074")},
		Snippet: types.Snippet{
			Before:   []byte("some random context\n"),
			Matching: []byte("11811f784531053132519844d047186074"),
			After:    []byte("\nmore context"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "no Jenkins URL")
}

func TestJenkinsValidator_MissingUser(t *testing.T) {
	v := NewJenkinsValidator()

	match := &types.Match{
		RuleID: "np.jenkins.1",
		Groups: [][]byte{[]byte("11811f784531053132519844d047186074")},
		Snippet: types.Snippet{
			Before:   []byte("JENKINS_URL=https://jenkins.example.com\n"),
			Matching: []byte("11811f784531053132519844d047186074"),
			After:    []byte("\nmore context"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "no Jenkins username")
}

func TestJenkinsValidator_SkipsLocalhost(t *testing.T) {
	v := NewJenkinsValidator()

	match := &types.Match{
		RuleID: "np.jenkins.1",
		Groups: [][]byte{[]byte("11811f784531053132519844d047186074")},
		Snippet: types.Snippet{
			Before:   []byte("JENKINS_URL=http://localhost:8080\nJENKINS_USER=admin\n"),
			Matching: []byte("11811f784531053132519844d047186074"),
			After:    []byte(""),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "localhost")
}

func TestJenkinsValidator_ConnectionError(t *testing.T) {
	v := NewJenkinsValidator()

	match := &types.Match{
		RuleID: "np.jenkins.1",
		Groups: [][]byte{[]byte("11811f784531053132519844d047186074")},
		Snippet: types.Snippet{
			Before:   []byte("JENKINS_URL=https://nonexistent.invalid\nJENKINS_USER=admin\n"),
			Matching: []byte("11811f784531053132519844d047186074"),
			After:    []byte(""),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "connection failed")
}
