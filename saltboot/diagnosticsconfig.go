package saltboot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v2"
)

const (
	diagnosticsConfigKey        = "SALTBOOT_DIAGNOSTICS_CONFIG"
	defaultDiagnosticsConfigLoc = "/etc/salt-bootstrap/diagnostics.yml"
)

// DiagnosticsConfig holds the limits, thresholds and lists of the diagnostics routes. The defaults can be overridden
// with a YAML file at defaultDiagnosticsConfigLoc (or where SALTBOOT_DIAGNOSTICS_CONFIG points), read once at startup.
// A key of the file replaces the default as a whole, a list or map included; keys the file leaves out keep the default.
type DiagnosticsConfig struct {
	// how long the distribute route waits for a single target
	DistributeTimeout time.Duration `yaml:"distributeTimeout"`
	// how many targets the distribute route contacts at a time; the others wait for a free slot, in request order, and
	// their distributeTimeout only starts when they are contacted, so the whole call can take
	// ceil(targets / maxParallelTargets) * distributeTimeout when the targets are slow
	MaxParallelTargets int `yaml:"maxParallelTargets"`
	// how long a node collects; probes still running then are listed in timedOutProbes
	ProbeDeadline time.Duration `yaml:"probeDeadline"`
	// the TCP check of a master port
	DialTimeout time.Duration `yaml:"dialTimeout"`
	// short commands: hostname, faillock and systemctl show
	CommandTimeout time.Duration `yaml:"commandTimeout"`
	// the lookup of the node's own FQDN
	LookupTimeout time.Duration `yaml:"lookupTimeout"`
	// salt-call has to start a python interpreter, which takes a while on a loaded node
	SaltCallTimeout time.Duration `yaml:"saltCallTimeout"`
	LvmTimeout      time.Duration `yaml:"lvmTimeout"`

	DefaultLogLines int `yaml:"defaultLogLines"`
	MaxLogLines     int `yaml:"maxLogLines"`
	// only the end of a log is read, so a huge log can neither slow the probe down nor bloat the response
	LogWindowBytes     int `yaml:"logWindowBytes"`
	MaxLineBytes       int `yaml:"maxLineBytes"`
	MaxAdditionalUnits int `yaml:"maxAdditionalUnits"`
	MaxUnitNameLength  int `yaml:"maxUnitNameLength"`
	// the job lists of a node are cut to the oldest jobs, as a node with thousands of stale proc files would bloat the response
	MaxJobs         int `yaml:"maxJobs"`
	CheckTextLength int `yaml:"checkTextLength"`
	CheckListLength int `yaml:"checkListLength"`

	// a filesystem with less than this share of its space or inodes left is a warning, below the second one a failure
	LowFreeWarnPercent float64 `yaml:"lowFreeWarnPercent"`
	LowFreeFailPercent float64 `yaml:"lowFreeFailPercent"`
	// the load per CPU above which tasks have been queuing for the last five minutes
	LoadPerCpuWarn float64 `yaml:"loadPerCpuWarn"`
	// the nodes are not probed at the same instant (the fan-out, the probe deadline and the second resolution of the
	// time add up), so a node is only reported when its clock is this far from the median of the nodes; Kerberos
	// rejects a skew over 5 minutes, which is the failure
	ClockSkewWarn time.Duration `yaml:"clockSkewWarn"`
	ClockSkewFail time.Duration `yaml:"clockSkewFail"`
	// a salt job whose proc file is older than this is reported as long-running
	JobAgeWarn time.Duration `yaml:"jobAgeWarn"`
	// worker_threads of salt-master when the configuration has none; a salt-master with more than
	// MinionsPerWorkerThread accepted minions per worker thread is reported
	DefaultWorkerThreads   int `yaml:"defaultWorkerThreads"`
	MinionsPerWorkerThread int `yaml:"minionsPerWorkerThread"`
	// the password of saltuser is reported when it expires within this many days
	PasswordExpiryWarnDays int `yaml:"passwordExpiryWarnDays"`
	// an active unit restarted by systemd at least crashLoopRestarts times whose current process is younger than
	// crashLoopUptime is crash-looping
	CrashLoopRestarts int           `yaml:"crashLoopRestarts"`
	CrashLoopUptime   time.Duration `yaml:"crashLoopUptime"`

	// unit and log file name -> required; only salt-master nodes run salt-master and salt-api, so a missing
	// optional unit or log is left out of the result instead of being reported as an error
	Units       map[string]bool `yaml:"units"`
	LogFiles    map[string]bool `yaml:"logFiles"`
	MasterPorts []int           `yaml:"masterPorts"`
	// mount points that are reported with their own usage when they are separate filesystems, as a full /var or
	// /var/log is a common cause of failures that df on / does not show
	MountPoints []string `yaml:"mountPoints"`

	// loadError is why the file could not be used; the defaults are in effect then
	loadError string
}

func defaultDiagnosticsConfig() *DiagnosticsConfig {
	return &DiagnosticsConfig{
		DistributeTimeout:  20 * time.Second,
		MaxParallelTargets: 50,
		ProbeDeadline:      10 * time.Second,
		DialTimeout:        3 * time.Second,
		CommandTimeout:     3 * time.Second,
		LookupTimeout:      3 * time.Second,
		SaltCallTimeout:    5 * time.Second,
		LvmTimeout:         5 * time.Second,

		DefaultLogLines:    50,
		MaxLogLines:        200,
		LogWindowBytes:     64 * 1024,
		MaxLineBytes:       1024,
		MaxAdditionalUnits: 20,
		MaxUnitNameLength:  255,
		MaxJobs:            100,
		CheckTextLength:    80,
		CheckListLength:    5,

		LowFreeWarnPercent:     10,
		LowFreeFailPercent:     2,
		LoadPerCpuWarn:         2,
		ClockSkewWarn:          120 * time.Second,
		ClockSkewFail:          300 * time.Second,
		JobAgeWarn:             time.Hour,
		DefaultWorkerThreads:   5,
		MinionsPerWorkerThread: 25,
		PasswordExpiryWarnDays: 14,
		CrashLoopRestarts:      3,
		CrashLoopUptime:        time.Minute,

		Units:       map[string]bool{"salt-bootstrap": true, "salt-minion": true, "salt-master": false, "salt-api": false},
		LogFiles:    map[string]bool{"/var/log/salt/minion": true, "/var/log/saltboot.log": true, "/var/log/salt/master": false, "/var/log/salt/api": false},
		MasterPorts: []int{4505, 4506},
		MountPoints: []string{"/var", "/var/log", "/srv", "/tmp", "/opt"},
	}
}

// diagnosticsConfig is set once at startup and replaced as a whole in tests, so readers never see a half-written one.
var diagnosticsConfig atomic.Pointer[DiagnosticsConfig]

func init() {
	diagnosticsConfig.Store(defaultDiagnosticsConfig())
}

// diagConfig returns the configuration in effect. It must not be modified.
func diagConfig() *DiagnosticsConfig {
	return diagnosticsConfig.Load()
}

// LoadDiagnosticsConfig reads the diagnostics configuration file at startup. A missing file means the defaults; an
// unusable one is logged and means the defaults as well, with the reason reported in every diagnostics response.
func LoadDiagnosticsConfig() {
	path := strings.TrimSpace(os.Getenv(diagnosticsConfigKey))
	if path == "" {
		path = defaultDiagnosticsConfigLoc
	}
	config := readDiagnosticsConfig(path)
	if config.loadError != "" {
		log.Printf("[LoadDiagnosticsConfig] [ERROR] using the default diagnostics configuration: %s", config.loadError)
	} else {
		log.Printf("[LoadDiagnosticsConfig] diagnostics configuration: %s", path)
	}
	diagnosticsConfig.Store(config)
}

func readDiagnosticsConfig(path string) *DiagnosticsConfig {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return defaultDiagnosticsConfig()
	}
	if err == nil {
		var config *DiagnosticsConfig
		if config, err = parseDiagnosticsConfig(b); err == nil {
			return config
		}
	}
	config := defaultDiagnosticsConfig()
	config.loadError = path + ": " + err.Error()
	return config
}

// parseDiagnosticsConfig applies the file over the defaults. Unknown keys are an error, so a typo does not silently
// leave a default in place.
func parseDiagnosticsConfig(b []byte) (*DiagnosticsConfig, error) {
	if err := checkDurationsHaveUnits(b); err != nil {
		return nil, err
	}
	config := defaultDiagnosticsConfig()
	// yaml adds to a map it decodes into, so the maps start empty to be replaced like every other key
	config.Units, config.LogFiles = nil, nil
	if err := yaml.UnmarshalStrict(b, config); err != nil {
		return nil, err
	}
	defaults := defaultDiagnosticsConfig()
	if config.Units == nil {
		config.Units = defaults.Units
	}
	if config.LogFiles == nil {
		config.LogFiles = defaults.LogFiles
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	return config, nil
}

// checkDurationsHaveUnits rejects a duration given as a plain number: yaml reads "probeDeadline: 15" as 15ns.
func checkDurationsHaveUnits(b []byte) error {
	var raw map[string]interface{}
	if err := yaml.Unmarshal(b, &raw); err != nil {
		return err
	}
	var errs []string
	configType := reflect.TypeOf(DiagnosticsConfig{})
	for i := 0; i < configType.NumField(); i++ {
		field := configType.Field(i)
		key := field.Tag.Get("yaml")
		if value, given := raw[key]; given && field.Type == reflect.TypeOf(time.Duration(0)) {
			if _, isText := value.(string); !isText {
				errs = append(errs, fmt.Sprintf("%s must be a duration with a unit, e.g. 15s, got %v", key, value))
			}
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func (c *DiagnosticsConfig) validate() error {
	var errs []string
	for name, value := range map[string]time.Duration{
		"distributeTimeout": c.DistributeTimeout, "probeDeadline": c.ProbeDeadline, "dialTimeout": c.DialTimeout,
		"commandTimeout": c.CommandTimeout, "lookupTimeout": c.LookupTimeout, "saltCallTimeout": c.SaltCallTimeout,
		"lvmTimeout": c.LvmTimeout, "clockSkewWarn": c.ClockSkewWarn, "crashLoopUptime": c.CrashLoopUptime, "clockSkewFail": c.ClockSkewFail, "jobAgeWarn": c.JobAgeWarn,
	} {
		if value <= 0 {
			errs = append(errs, fmt.Sprintf("%s must be positive, got %s", name, value))
		}
	}
	for name, value := range map[string]int{
		"maxParallelTargets": c.MaxParallelTargets, "maxLogLines": c.MaxLogLines, "logWindowBytes": c.LogWindowBytes, "maxLineBytes": c.MaxLineBytes,
		"maxAdditionalUnits": c.MaxAdditionalUnits, "maxUnitNameLength": c.MaxUnitNameLength, "maxJobs": c.MaxJobs,
		"checkTextLength": c.CheckTextLength, "checkListLength": c.CheckListLength,
		"defaultWorkerThreads": c.DefaultWorkerThreads, "crashLoopRestarts": c.CrashLoopRestarts, "minionsPerWorkerThread": c.MinionsPerWorkerThread,
	} {
		if value <= 0 {
			errs = append(errs, fmt.Sprintf("%s must be positive, got %d", name, value))
		}
	}
	if c.DefaultLogLines < 0 || c.DefaultLogLines > c.MaxLogLines {
		errs = append(errs, fmt.Sprintf("defaultLogLines must be between 0 and maxLogLines (%d), got %d", c.MaxLogLines, c.DefaultLogLines))
	}
	if c.PasswordExpiryWarnDays < 0 {
		errs = append(errs, fmt.Sprintf("passwordExpiryWarnDays must not be negative, got %d", c.PasswordExpiryWarnDays))
	}
	if c.LowFreeFailPercent < 0 || c.LowFreeFailPercent > c.LowFreeWarnPercent || c.LowFreeWarnPercent > 100 {
		errs = append(errs, fmt.Sprintf("0 <= lowFreeFailPercent <= lowFreeWarnPercent <= 100 does not hold for %g and %g",
			c.LowFreeFailPercent, c.LowFreeWarnPercent))
	}
	if c.LoadPerCpuWarn <= 0 {
		errs = append(errs, fmt.Sprintf("loadPerCpuWarn must be positive, got %g", c.LoadPerCpuWarn))
	}
	if c.ClockSkewFail < c.ClockSkewWarn {
		errs = append(errs, fmt.Sprintf("clockSkewFail (%s) must not be below clockSkewWarn (%s)", c.ClockSkewFail, c.ClockSkewWarn))
	}
	for _, unit := range slices.Sorted(maps.Keys(c.Units)) {
		// the names are passed to systemctl, so they follow the rules of the requested units
		if len(unit) > c.MaxUnitNameLength || !diagnosticsUnitNamePattern.MatchString(unit) {
			errs = append(errs, fmt.Sprintf("invalid unit name %q", unit))
		}
	}
	for _, path := range slices.Sorted(maps.Keys(c.LogFiles)) {
		if !isCleanAbsolutePath(path) {
			errs = append(errs, fmt.Sprintf("log file %q must be a clean absolute path", path))
		}
	}
	for _, path := range c.MountPoints {
		if !isCleanAbsolutePath(path) {
			errs = append(errs, fmt.Sprintf("mount point %q must be a clean absolute path", path))
		}
	}
	for _, port := range c.MasterPorts {
		if port < 1 || port > 65535 {
			errs = append(errs, fmt.Sprintf("master port %d is out of range", port))
		}
	}
	if len(errs) > 0 {
		// the duration and number checks run over maps, so their order is fixed here
		slices.Sort(errs)
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// probeTimeouts are the timeouts of the single commands and lookups of one collection.
type probeTimeouts struct {
	command, lookup, saltCall, lvm, dial time.Duration
}

// timeoutsWithin returns the configured timeouts cut to the probe deadline: the deadline can come from the request,
// and a single command waiting longer than the whole collection could only ever time out.
func (c *DiagnosticsConfig) timeoutsWithin(deadline time.Duration) probeTimeouts {
	return probeTimeouts{
		command:  min(c.CommandTimeout, deadline),
		lookup:   min(c.LookupTimeout, deadline),
		saltCall: min(c.SaltCallTimeout, deadline),
		lvm:      min(c.LvmTimeout, deadline),
		dial:     min(c.DialTimeout, deadline),
	}
}

// fingerprint identifies the settings, so nodes can be compared without listing them all. It covers every setting,
// not the load error; json orders the map keys, so equal settings give the same fingerprint.
func (c *DiagnosticsConfig) fingerprint() string {
	b, err := json.Marshal(c)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

func isCleanAbsolutePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}
