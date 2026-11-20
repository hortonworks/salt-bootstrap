package saltboot

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// setDiagnosticsConfig runs the test with a copy of the current configuration changed by change, and puts the
// original back afterwards. The copy is stored as a whole, so probes still running from an earlier test are safe.
func setDiagnosticsConfig(t *testing.T, change func(c *DiagnosticsConfig)) {
	t.Helper()
	original := diagConfig()
	changed := *original
	change(&changed)
	diagnosticsConfig.Store(&changed)
	t.Cleanup(func() { diagnosticsConfig.Store(original) })
}

func writeDiagnosticsConfig(t *testing.T, content string) string {
	t.Helper()
	path := t.TempDir() + "/diagnostics.yml"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadDiagnosticsConfigWithoutAFile(t *testing.T) {
	config := readDiagnosticsConfig(t.TempDir() + "/missing.yml")

	if !reflect.DeepEqual(config, defaultDiagnosticsConfig()) {
		t.Errorf("expected the defaults without a file, got %+v", config)
	}
}

func TestReadDiagnosticsConfigOverridesOnlyTheGivenKeys(t *testing.T) {
	path := writeDiagnosticsConfig(t, strings.Join([]string{
		"distributeTimeout: 45s",
		"probeDeadline: 15s",
		"logWindowBytes: 131072",
		"lowFreeWarnPercent: 15",
		"clockSkewWarn: 1m",
		"units:",
		"  salt-minion: true",
		"  example-agent: false",
		"masterPorts: [4506]",
		"mountPoints: [/var, /data1]",
	}, "\n"))

	config := readDiagnosticsConfig(path)

	if config.loadError != "" {
		t.Fatalf("unexpected error: %s", config.loadError)
	}
	if config.DistributeTimeout != 45*time.Second || config.ProbeDeadline != 15*time.Second || config.LogWindowBytes != 131072 ||
		config.LowFreeWarnPercent != 15 || config.ClockSkewWarn != time.Minute {
		t.Errorf("the given values were not applied: %+v", config)
	}
	// a map or list key replaces the default as a whole
	if !reflect.DeepEqual(config.Units, map[string]bool{"salt-minion": true, "example-agent": false}) ||
		!reflect.DeepEqual(config.MasterPorts, []int{4506}) || !reflect.DeepEqual(config.MountPoints, []string{"/var", "/data1"}) {
		t.Errorf("the lists were not replaced: %v %v %v", config.Units, config.MasterPorts, config.MountPoints)
	}
	defaults := defaultDiagnosticsConfig()
	if config.DialTimeout != defaults.DialTimeout || config.MaxJobs != defaults.MaxJobs || !reflect.DeepEqual(config.LogFiles, defaults.LogFiles) {
		t.Errorf("the keys the file leaves out must keep their defaults: %+v", config)
	}
}

func TestReadDiagnosticsConfigFallsBackToTheDefaults(t *testing.T) {
	cases := []struct {
		name    string
		content string
		error   string
	}{
		{"broken yaml", "probeDeadline: [", "yaml: line 1"},
		{"unknown key", "probeDeadlin: 15s", "field probeDeadlin not found"},
		{"duration without a unit", "probeDeadline: 15", "probeDeadline must be a duration with a unit, e.g. 15s, got 15"},
		{"duration without a unit in a quoted string", "probeDeadline: '15'", "cannot unmarshal !!str `15` into time.Duration"},
		{"negative timeout", "dialTimeout: -1s", "dialTimeout must be positive, got -1s"},
		{"zero count", "maxJobs: 0", "maxJobs must be positive, got 0"},
		{"default lines over the maximum", "defaultLogLines: 300", "defaultLogLines must be between 0 and maxLogLines (200), got 300"},
		{"fail above warn", "lowFreeFailPercent: 20", "0 <= lowFreeFailPercent <= lowFreeWarnPercent <= 100 does not hold for 20 and 10"},
		{"skew fail below warn", "clockSkewFail: 1m", "clockSkewFail (1m0s) must not be below clockSkewWarn (2m0s)"},
		{"unit name", "units: {'--all': true}", `invalid unit name "--all"`},
		{"relative log file", "logFiles: {var/log/x: true}", `log file "var/log/x" must be a clean absolute path`},
		{"log file with dots", "logFiles: {/var/log/../../etc/shadow: true}", `log file "/var/log/../../etc/shadow" must be a clean absolute path`},
		{"mount point", "mountPoints: [/var/]", `mount point "/var/" must be a clean absolute path`},
		{"port", "masterPorts: [0, 70000]", "master port 0 is out of range; master port 70000 is out of range"},
		{"several errors", "dialTimeout: 0s\nmaxJobs: -1", "dialTimeout must be positive, got 0s; maxJobs must be positive, got -1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := writeDiagnosticsConfig(t, c.content)

			config := readDiagnosticsConfig(path)

			if !strings.HasPrefix(config.loadError, path+": ") || !strings.Contains(config.loadError, c.error) {
				t.Errorf("expected an error containing %q, got %q", c.error, config.loadError)
			}
			withoutError := *config
			withoutError.loadError = ""
			if !reflect.DeepEqual(&withoutError, defaultDiagnosticsConfig()) {
				t.Errorf("expected the defaults, got %+v", config)
			}
		})
	}
}

func TestReadDiagnosticsConfigReportsAnUnreadableFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read the file anyway")
	}
	path := writeDiagnosticsConfig(t, "probeDeadline: 15s")
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}

	config := readDiagnosticsConfig(path)

	if !strings.Contains(config.loadError, "permission denied") || config.ProbeDeadline != defaultDiagnosticsConfig().ProbeDeadline {
		t.Errorf("expected the defaults and the read error, got %+v", config)
	}
}

func TestLoadDiagnosticsConfigUsesTheEnvironmentOverride(t *testing.T) {
	original := diagConfig()
	t.Cleanup(func() { diagnosticsConfig.Store(original) })
	path := writeDiagnosticsConfig(t, "maxJobs: 7")
	t.Setenv(diagnosticsConfigKey, path)
	var logged bytes.Buffer
	originalOutput := log.Writer()
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(originalOutput) })

	LoadDiagnosticsConfig()

	if diagConfig().MaxJobs != 7 || !strings.Contains(logged.String(), "diagnostics configuration: "+path) {
		t.Errorf("expected the file of %s to be loaded, got %+v, log %q", diagnosticsConfigKey, diagConfig(), logged.String())
	}

	writeDiagnosticsConfig(t, "")
	t.Setenv(diagnosticsConfigKey, path+".missing")
	LoadDiagnosticsConfig()

	if diagConfig().MaxJobs != defaultDiagnosticsConfig().MaxJobs || diagConfig().loadError != "" {
		t.Errorf("expected the defaults without the file, got %+v", diagConfig())
	}
}

func TestDiagnosticsResponsesReportTheConfigError(t *testing.T) {
	mockCommands(t, map[string]string{"/bin/systemctl show": "LoadState=loaded\n", "timedatectl show": "NTP=yes\n"})
	setDiagnosticsConfig(t, func(c *DiagnosticsConfig) { c.loadError = "/etc/salt-bootstrap/diagnostics.yml: field x not found" })

	req := httptest.NewRequest("POST", "/saltboot/diagnostics", bytes.NewBufferString(`{"logLines": 0}`))
	req.Header.Set("salt-minion-base-dir", t.TempDir())
	w := httptest.NewRecorder()
	DiagnosticsHandler(w, req)

	var node NodeDiagnostics
	if err := json.Unmarshal(w.Body.Bytes(), &node); err != nil {
		t.Fatal(err)
	}
	if node.ConfigError != "/etc/salt-bootstrap/diagnostics.yml: field x not found" {
		t.Errorf("expected the config error in the node response, got %q", node.ConfigError)
	}

	distributed := DiagnosticsResponse{Nodes: []NodeDiagnostics{node}, ConfigError: diagConfig().loadError}
	if b, _ := json.Marshal(distributed); !strings.Contains(string(b), `"configError":"/etc/salt-bootstrap/diagnostics.yml: field x not found"}`) {
		t.Errorf("expected the config error in the distribute response, got %s", b)
	}
}

func TestDiagnosticsConfigLimitsAreApplied(t *testing.T) {
	setDiagnosticsConfig(t, func(c *DiagnosticsConfig) {
		c.MaxLineBytes = 10
		c.MaxAdditionalUnits = 1
		c.MountPoints = []string{"/data"}
	})

	if line := capLine(strings.Repeat("x", 20)); line != "xxxxxxxxxx...[truncated]" {
		t.Errorf("expected the line capped at 10 bytes, got %q", line)
	}
	if probed, rejected := (DiagnosticsRequest{AdditionalUnits: []string{"a", "b"}}).selectAdditionalUnits(); len(probed) != 1 ||
		len(rejected) != 1 || rejected[0].Rejected != "more than 1 additional units requested" {
		t.Errorf("expected the configured unit limit, got %v %+v", probed, rejected)
	}
	baseDir := t.TempDir()
	for _, dir := range []string{"/data", "/var"} {
		if err := os.MkdirAll(baseDir+dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	writeTestFile(t, baseDir, "/proc/self/mounts", "/dev/sdb1 /data xfs rw 0 0\n/dev/sdc1 /var xfs rw 0 0\n")
	mounts, err := probeMounts(baseDir)
	if err != nil || len(mounts) != 1 || mounts[0].Path != "/data" {
		t.Errorf("expected only the configured mount point, got %+v, %v", mounts, err)
	}
}

// TestDiagnosticsDocConfigMatchesTheDefaults keeps the example file of DIAGNOSTICS.md in line with the code.
func TestDiagnosticsDocConfigMatchesTheDefaults(t *testing.T) {
	doc, err := os.ReadFile("../DIAGNOSTICS.md")
	if err != nil {
		t.Fatal(err)
	}
	_, example, found := strings.Cut(string(doc), "```yaml\n")
	example, _, _ = strings.Cut(example, "```")
	if !found {
		t.Fatal("no yaml example in DIAGNOSTICS.md")
	}

	config, err := parseDiagnosticsConfig([]byte(example))

	if err != nil {
		t.Fatalf("the DIAGNOSTICS.md example is not a valid configuration: %s", err)
	}
	if !reflect.DeepEqual(config, defaultDiagnosticsConfig()) {
		t.Errorf("the DIAGNOSTICS.md example differs from the defaults:\n%+v\n%+v", config, defaultDiagnosticsConfig())
	}
	keys := 0
	for _, line := range strings.Split(example, "\n") {
		if line != "" && !strings.HasPrefix(line, "#") {
			keys++
		}
	}
	if fields := reflect.TypeOf(DiagnosticsConfig{}).NumField() - 1; keys != fields {
		t.Errorf("the DIAGNOSTICS.md example has %d keys, the configuration %d", keys, fields)
	}
}
