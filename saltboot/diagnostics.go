package saltboot

import (
	"bufio"
	"cmp"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v2"
)

// The limits, thresholds and lists the diagnostics use are in DiagnosticsConfig, which a file can override.
const (
	// the password never expires when maxDays is 99999 (or more) in /etc/shadow
	shadowNoExpiryDays = 99999
	secondsPerDay      = 24 * 60 * 60

	diagnosticsCheckOk      = "ok"
	diagnosticsCheckWarn    = "warn"
	diagnosticsCheckFail    = "fail"
	diagnosticsCheckSkipped = "skipped"
	// the check itself failed, e.g. it panicked on unexpected data
	diagnosticsCheckError = "error"
	// /etc/shadow must not allow more than this, while /etc/passwd and /etc/group must be readable by all (0644)
	diagnosticsShadowMaxMode = 0640
	diagnosticsReadableMode  = 0444
)

var (
	// salt-master key directory -> key state, in the order salt-key lists them
	diagnosticsMasterKeyDirs = []struct{ dir, state string }{
		{"minions", "accepted"}, {"minions_pre", "pending"}, {"minions_rejected", "rejected"}, {"minions_denied", "denied"},
	}

	// system files whose owner and mode the saltUser section reports, as a wrong owner or mode of /etc/shadow breaks PAM
	diagnosticsAccountFiles = []string{"/etc/passwd", "/etc/shadow", "/etc/group"}

	dialTimeout    = net.DialTimeout
	lookPath       = exec.LookPath
	interfaceAddrs = net.InterfaceAddrs
	// diagnosticsNow is replaced in tests, so the password expiry can be checked against a fixed date
	diagnosticsNow = time.Now

	// Secret redaction. The keywords password, passwd, secret, token, signature, sign_key, signkey and credential(s)
	// match anywhere inside a key made of [A-Za-z0-9_.-] (db_password, adminPassword, X-Auth-Token), the key is kept
	// and only the value is replaced. "pass" and "pwd" are only keywords as a whole key or a delimited segment
	// (pass, db_pass, admin-pwd), otherwise "bypass=false" or "compass: n" would be redacted.
	diagnosticsSecretPattern = regexp.MustCompile(`(?i)([A-Za-z0-9_.-]*(?:password|passwd|secret|token|signature|sign_key|signkey|credentials?)[A-Za-z0-9_.-]*["']?\s*[:=]\s*)(?:(")[^"]*"|(')[^']*'|["']?[^\s"',}\]]+)`)
	diagnosticsPassPattern   = regexp.MustCompile(`(?i)((?:^|[^A-Za-z0-9_.-])(?:[A-Za-z0-9_.-]*[_.-])?(?:pass|pwd)["']?\s*[:=]\s*)(?:(")[^"]*"|(')[^']*'|["']?[^\s"',}\]]+)`)
	// whitespace separates the key and the value only in the command-line flag form: --password hunter2
	diagnosticsFlagPattern = regexp.MustCompile(`(?i)((?:^|\s)--?(?:[A-Za-z0-9_.-]*(?:password|passwd|secret|token|signature|sign_key|signkey|credentials?)[A-Za-z0-9_.-]*|(?:[A-Za-z0-9_.-]*[_.-])?(?:pass|pwd))\s+)(?:(")[^"]*"|(')[^']*'|[^\s"',}\]-][^\s"',}\]]*)`)
	// scheme://user:secret@host
	diagnosticsURLUserinfoPattern = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://[^\s/:@"']+:)[^\s/"']+@`)
	diagnosticsAuthPattern        = regexp.MustCompile(`(?i)\b(basic|bearer)\s+[A-Za-z0-9+/=._~-]+`)
	diagnosticsUnitNamePattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._:-]*$`)
	diagnosticsSaltVersionDir     = regexp.MustCompile(`^salt-[0-9].*\.(dist-info|egg-info)$`)
	diagnosticsPythonPattern      = regexp.MustCompile(`python(\d+(?:\.\d+)*)`)
	diagnosticsSaltCallVersion    = regexp.MustCompile(`(?m)^salt(?:-call)?\s+(\d\S*)`)
	// salt job ids are YYYYMMDDhhmmssffffff
	diagnosticsJidPattern    = regexp.MustCompile(`^\d{20}$`)
	diagnosticsWorkerThreads = regexp.MustCompile(`(?m)^worker_threads:\s*(\d+)`)
)

// lookupHost resolves the node's own FQDN; tests replace it.
var lookupHost = func(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

type DiagnosticsRequest struct {
	Targets  []string `json:"targets,omitempty"`
	LogLines *int     `json:"logLines,omitempty"`
	// AdditionalUnits are extra systemd units to report next to the built-in salt units, e.g. a monitoring agent. A unit that
	// is not a valid name or exceeds the limits is not probed but reported as rejected; the request still runs.
	AdditionalUnits []string `json:"additionalUnits,omitempty"`
	// SaltUserPassword is the expected saltuser password; when given, the nodes with a saltuser entry check
	// it against /etc/shadow. It is never logged nor part of a response. The request reaches every target, so leave it
	// out of requests that do not need it.
	SaltUserPassword string `json:"saltUserPassword,omitempty"`
	// ProbeDeadline is how long every node collects, e.g. "10s". The request is forwarded unchanged, so all nodes use
	// the same value; without it each node uses the probeDeadline of its own configuration.
	ProbeDeadline string `json:"probeDeadline,omitempty"`
}

type DiagnosticsResponse struct {
	Nodes []NodeDiagnostics `json:"nodes,omitempty"`
	// Checks are the cross-node findings of the distribute route, one entry per check id in a fixed order
	Checks     []DiagnosticsCheck `json:"checks,omitempty"`
	ErrorText  string             `json:"errorText,omitempty"`
	StatusCode int                `json:"statusCode,omitempty"`
	// ConfigFingerprint identifies the diagnostics configuration of the node running the fan-out
	ConfigFingerprint string `json:"configFingerprint,omitempty"`
	// ConfigError is why the diagnostics configuration file of the node running the fan-out could not be used, so
	// its distribute timeout and check thresholds are the defaults
	ConfigError string `json:"configError,omitempty"`
}

// DiagnosticsCheck is the outcome of one check over all collected nodes. Status is ok, warn, fail, skipped or error;
// a check is skipped when the data it needs is absent, e.g. there is no salt-master among the targets, and it is
// an error when the check itself failed.
type DiagnosticsCheck struct {
	Id      string `json:"id"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
	// Nodes are the addresses of the nodes the findings are about
	Nodes []string `json:"nodes,omitempty"`
}

type NodeDiagnostics struct {
	Address    string `json:"address,omitempty"`
	StatusCode int    `json:"statusCode,omitempty"`
	ErrorText  string `json:"errorText,omitempty"`
	Version    string `json:"version,omitempty"`
	// ConfigFingerprint identifies the node's diagnostics configuration; nodes with the same one share their settings
	ConfigFingerprint string `json:"configFingerprint,omitempty"`
	// ConfigError is why the node's diagnostics configuration file could not be used, so it ran with the defaults
	ConfigError string `json:"configError,omitempty"`
	// ProbeDeadline is the deadline the node collected with, from the request or its own configuration
	ProbeDeadline  string               `json:"probeDeadline,omitempty"`
	Units          []UnitDiagnostics    `json:"units,omitempty"`
	Minion         *MinionDiagnostics   `json:"minion,omitempty"`
	Time           *TimeDiagnostics     `json:"time,omitempty"`
	Resources      *ResourceDiagnostics `json:"resources,omitempty"`
	Master         *MasterDiagnostics   `json:"master,omitempty"`
	SaltUser       *SaltUserDiagnostics `json:"saltUser,omitempty"`
	Host           *HostDiagnostics     `json:"host,omitempty"`
	Jobs           *SaltJobsDiagnostics `json:"jobs,omitempty"`
	Logs           []LogDiagnostics     `json:"logs,omitempty"`
	TimedOutProbes []string             `json:"timedOutProbes,omitempty"`
	// FailedProbes are the probes that panicked, as "<probe>: <panic value>"
	FailedProbes []string `json:"failedProbes,omitempty"`
	// contactOffset is how long after the first target of the fan-out this node was contacted, so the clock check can
	// tell the delay of the queue from skew. It is only known to the fan-out node, hence not in the response.
	contactOffset time.Duration
}

type UnitDiagnostics struct {
	Name                 string `json:"name"`
	LoadState            string `json:"loadState,omitempty"`
	ActiveState          string `json:"activeState,omitempty"`
	SubState             string `json:"subState,omitempty"`
	ActiveEnterTimestamp string `json:"activeEnterTimestamp,omitempty"`
	NRestarts            *int   `json:"nRestarts,omitempty"`
	MainPid              *int   `json:"mainPid,omitempty"`
	// Process describes the unit's main process; it is only present while the unit has one
	Process *ProcessDiagnostics `json:"process,omitempty"`
	Error   string              `json:"error,omitempty"`
	// Rejected is why a requested unit was not probed, e.g. an invalid name or one over the limit
	Rejected string `json:"rejected,omitempty"`
}

type ProcessDiagnostics struct {
	// State is the kernel's process state, e.g. "S (sleeping)"; "D (disk sleep)" means stuck waiting for I/O
	State         string  `json:"state,omitempty"`
	RssKb         *uint64 `json:"rssKb,omitempty"`
	Threads       *int    `json:"threads,omitempty"`
	OpenFds       *int    `json:"openFds,omitempty"`
	UptimeSeconds *int64  `json:"uptimeSeconds,omitempty"`
	Error         string  `json:"error,omitempty"`
}

type MinionDiagnostics struct {
	Masters     []MinionMasterDiagnostics `json:"masters,omitempty"`
	IdConfig    string                    `json:"idConfig,omitempty"`
	CachedId    string                    `json:"cachedId,omitempty"`
	Fingerprint string                    `json:"fingerprint,omitempty"`
	// MasterKeyFingerprint and MasterSignKeyFingerprint are the fingerprints of the salt-master keys this minion
	// holds; they are comparable with master.keyFingerprint and master.signKeyFingerprint, and a minion holding
	// a stale master key cannot authenticate the master
	MasterKeyFingerprint     string `json:"masterKeyFingerprint,omitempty"`
	MasterSignKeyFingerprint string `json:"masterSignKeyFingerprint,omitempty"`
	SaltVersion              string `json:"saltVersion,omitempty"`
	PythonVersion            string `json:"pythonVersion,omitempty"`
	SaltInstallPath          string `json:"saltInstallPath,omitempty"`
	// VersionError is separate from Error, because the version is found by another probe
	VersionError string `json:"versionError,omitempty"`
	Error        string `json:"error,omitempty"`
}

// MinionMasterDiagnostics is a salt-master from the minion's master.conf with the reachability of its ports.
type MinionMasterDiagnostics struct {
	Id    string            `json:"id"`
	Ports []PortDiagnostics `json:"ports,omitempty"`
}

type PortDiagnostics struct {
	Port      int    `json:"port"`
	Reachable bool   `json:"reachable"`
	LatencyMs int64  `json:"latencyMs,omitempty"`
	Error     string `json:"error,omitempty"`
}

type TimeDiagnostics struct {
	Now             string `json:"now"`
	NtpEnabled      *bool  `json:"ntpEnabled,omitempty"`
	NtpSynchronized *bool  `json:"ntpSynchronized,omitempty"`
	Error           string `json:"error,omitempty"`
}

// ResourceDiagnostics is filled by two probes: resources (load, memory, disk.root) and lvm (disk.lvm), so a
// hanging lvs cannot take the rest with it. Each probe sets only its own part, in whichever order they finish.
type ResourceDiagnostics struct {
	Load   *LoadDiagnostics   `json:"load,omitempty"`
	Memory *MemoryDiagnostics `json:"memory,omitempty"`
	Disk   *DiskDiagnostics   `json:"disk,omitempty"`
	// BootTime is the time the system booted (RFC3339), from btime in /proc/stat
	BootTime      string `json:"bootTime,omitempty"`
	BootTimeError string `json:"bootTimeError,omitempty"`
}

type LoadDiagnostics struct {
	CpuCount int      `json:"cpuCount,omitempty"`
	Load1    *float64 `json:"load1,omitempty"`
	Load5    *float64 `json:"load5,omitempty"`
	Load15   *float64 `json:"load15,omitempty"`
	// the load averages divided by CpuCount: around 1 means every CPU is busy, above 1 means tasks are queuing
	Load1PerCpu  *float64 `json:"load1PerCpu,omitempty"`
	Load5PerCpu  *float64 `json:"load5PerCpu,omitempty"`
	Load15PerCpu *float64 `json:"load15PerCpu,omitempty"`
	Error        string   `json:"error,omitempty"`
}

type MemoryDiagnostics struct {
	TotalKb     *uint64 `json:"totalKb,omitempty"`
	AvailableKb *uint64 `json:"availableKb,omitempty"`
	// OomKills counts the processes the kernel's OOM killer killed since boot; it is nil on kernels older than 4.13
	OomKills *uint64 `json:"oomKills,omitempty"`
	Error    string  `json:"error,omitempty"`
}

type DiskDiagnostics struct {
	Root *FilesystemDiagnostics `json:"root,omitempty"`
	Lvm  *LvmDiagnostics        `json:"lvm,omitempty"`
	// Mounts lists the well-known directories that are a filesystem of their own, e.g. /var or /var/log
	Mounts      []MountDiagnostics `json:"mounts,omitempty"`
	MountsError string             `json:"mountsError,omitempty"`
}

type FilesystemDiagnostics struct {
	TotalBytes     *uint64 `json:"totalBytes,omitempty"`
	AvailableBytes *uint64 `json:"availableBytes,omitempty"`
	// TotalInodes and FreeInodes are nil on filesystems that allocate inodes dynamically, e.g. btrfs
	TotalInodes *uint64 `json:"totalInodes,omitempty"`
	FreeInodes  *uint64 `json:"freeInodes,omitempty"`
	Error       string  `json:"error,omitempty"`
}

type MountDiagnostics struct {
	Path string `json:"path"`
	FilesystemDiagnostics
}

func (d *NodeDiagnostics) resources() *ResourceDiagnostics {
	if d.Resources == nil {
		d.Resources = &ResourceDiagnostics{}
	}
	return d.Resources
}

func (r *ResourceDiagnostics) disk() *DiskDiagnostics {
	if r.Disk == nil {
		r.Disk = &DiskDiagnostics{}
	}
	return r.Disk
}

func (d *NodeDiagnostics) setLoadMemoryAndRoot(load *LoadDiagnostics, memory *MemoryDiagnostics, root *FilesystemDiagnostics) {
	resources := d.resources()
	resources.Load, resources.Memory, resources.disk().Root = load, memory, root
}

func (d *NodeDiagnostics) setBootTimeAndMounts(bootTime string, bootTimeErr error, mounts []MountDiagnostics, mountsErr error) {
	resources := d.resources()
	resources.BootTime = bootTime
	if bootTimeErr != nil {
		resources.BootTimeError = "stat: " + bootTimeErr.Error()
	}
	if len(mounts) > 0 || mountsErr != nil {
		disk := resources.disk()
		disk.Mounts = mounts
		if mountsErr != nil {
			disk.MountsError = "mounts: " + mountsErr.Error()
		}
	}
}

// setLvm leaves resources untouched on nodes without LVM tools, where lvm is nil.
func (d *NodeDiagnostics) setLvm(lvm *LvmDiagnostics) {
	if lvm != nil {
		d.resources().disk().Lvm = lvm
	}
}

// minion and master return the section, creating it when the probe that fills the rest of it has not finished
// yet, because the saltVersion probe adds to the sections of the minion and master probes in whichever order they finish.
func (d *NodeDiagnostics) minion() *MinionDiagnostics {
	if d.Minion == nil {
		d.Minion = &MinionDiagnostics{}
	}
	return d.Minion
}

func (d *NodeDiagnostics) master() *MasterDiagnostics {
	if d.Master == nil {
		d.Master = &MasterDiagnostics{Minions: []MasterMinionDiagnostics{}}
	}
	return d.Master
}

// setMinion keeps the version fields of the saltVersion probe, in case it finished first.
func (d *NodeDiagnostics) setMinion(minion MinionDiagnostics) {
	current := d.minion()
	minion.SaltVersion, minion.PythonVersion, minion.SaltInstallPath, minion.VersionError =
		current.SaltVersion, current.PythonVersion, current.SaltInstallPath, current.VersionError
	*current = minion
}

// setMaster leaves the master section alone on nodes that are no salt-master, where master is nil.
func (d *NodeDiagnostics) setMaster(master *MasterDiagnostics) {
	if master == nil {
		return
	}
	current := d.master()
	master.SaltVersion, master.VersionError = current.SaltVersion, current.VersionError
	*current = *master
}

// setSaltVersions creates no master section on nodes that are no salt-master, where master is nil.
func (d *NodeDiagnostics) setSaltVersions(minion saltVersion, master *saltVersion) {
	m := d.minion()
	m.SaltVersion, m.PythonVersion, m.SaltInstallPath, m.VersionError = minion.version, minion.pythonVersion, minion.installPath, minion.err
	if master != nil {
		d.master().SaltVersion, d.master().VersionError = master.version, master.err
	}
}

// LvmDiagnostics lists every LVM volume group and logical volume, so a full LV mounted outside / (e.g. /var),
// a full thin pool or an inactive LV is visible too.
type LvmDiagnostics struct {
	VolumeGroups   []VolumeGroupDiagnostics   `json:"volumeGroups,omitempty"`
	LogicalVolumes []LogicalVolumeDiagnostics `json:"logicalVolumes,omitempty"`
	Error          string                     `json:"error,omitempty"`
}

type VolumeGroupDiagnostics struct {
	Name      string  `json:"name"`
	SizeBytes *uint64 `json:"sizeBytes,omitempty"`
	FreeBytes *uint64 `json:"freeBytes,omitempty"`
	LvCount   *int    `json:"lvCount,omitempty"`
	PvCount   *int    `json:"pvCount,omitempty"`
}

type LogicalVolumeDiagnostics struct {
	VolumeGroup      string   `json:"volumeGroup"`
	Name             string   `json:"name"`
	Path             string   `json:"path,omitempty"`
	SizeBytes        *uint64  `json:"sizeBytes,omitempty"`
	Attributes       string   `json:"attributes,omitempty"`
	Active           bool     `json:"active"`
	Pool             string   `json:"pool,omitempty"`
	DataPercent      *float64 `json:"dataPercent,omitempty"`
	MetadataPercent  *float64 `json:"metadataPercent,omitempty"`
	MountPoints      []string `json:"mountPoints,omitempty"`
	FsType           string   `json:"fsType,omitempty"`
	FsTotalBytes     *uint64  `json:"fsTotalBytes,omitempty"`
	FsAvailableBytes *uint64  `json:"fsAvailableBytes,omitempty"`
	FsTotalInodes    *uint64  `json:"fsTotalInodes,omitempty"`
	FsFreeInodes     *uint64  `json:"fsFreeInodes,omitempty"`
	Error            string   `json:"error,omitempty"`
}

// MasterDiagnostics lists the minion keys a salt-master knows; it is only present on salt-master nodes.
type MasterDiagnostics struct {
	Minions []MasterMinionDiagnostics `json:"minions"`
	// KeyFingerprint and SignKeyFingerprint are comparable with minion.masterKeyFingerprint and
	// minion.masterSignKeyFingerprint on the minions
	KeyFingerprint     string `json:"keyFingerprint,omitempty"`
	SignKeyFingerprint string `json:"signKeyFingerprint,omitempty"`
	SaltVersion        string `json:"saltVersion,omitempty"`
	// VersionError is separate from Error, because the version is found by another probe
	VersionError string `json:"versionError,omitempty"`
	Error        string `json:"error,omitempty"`
}

type MasterMinionDiagnostics struct {
	Id       string `json:"id"`
	KeyState string `json:"keyState"`
	// Fingerprint is comparable with the fingerprint the minion reports about its own key
	Fingerprint string `json:"fingerprint,omitempty"`
	Error       string `json:"error,omitempty"`
}

// SaltUserDiagnostics describes the state of the saltuser account salt-api authenticates against through PAM; an
// expired or locked password makes salt-api answer 401. It never contains the password hash. It is only present
// on nodes that have a saltuser entry in /etc/shadow and on salt-master nodes.
type SaltUserDiagnostics struct {
	Present       bool `json:"present"`
	Locked        bool `json:"locked"`
	EmptyPassword bool `json:"emptyPassword"`
	// PasswordChangeRequired is set when the last change is 0, i.e. the password was forced to be changed at the next login
	PasswordChangeRequired bool   `json:"passwordChangeRequired"`
	LastChange             string `json:"lastChange,omitempty"`
	MinDays                *int   `json:"minDays,omitempty"`
	MaxDays                *int   `json:"maxDays,omitempty"`
	WarnDays               *int   `json:"warnDays,omitempty"`
	InactiveDays           *int   `json:"inactiveDays,omitempty"`
	// the dates are YYYY-MM-DD; PasswordExpiresAt is missing when the password never expires
	PasswordExpiresAt       string `json:"passwordExpiresAt,omitempty"`
	PasswordExpired         bool   `json:"passwordExpired"`
	DaysUntilPasswordExpiry *int   `json:"daysUntilPasswordExpiry,omitempty"`
	// PasswordInactiveAt is the day after which the account is disabled because the expired password was not changed
	PasswordInactiveAt string `json:"passwordInactiveAt,omitempty"`
	AccountExpiresAt   string `json:"accountExpiresAt,omitempty"`
	AccountExpired     bool   `json:"accountExpired"`
	PasswdEntry        bool   `json:"passwdEntry"`
	// ShadowNewLeftover means /etc/shadow.new exists, i.e. a password rotation was interrupted
	ShadowNewLeftover bool `json:"shadowNewLeftover"`
	// FaillockFailures is the number of valid failed logins faillock holds; it is nil when faillock is not installed
	FaillockFailures *int              `json:"faillockFailures,omitempty"`
	Files            []FileDiagnostics `json:"files,omitempty"`
	// PasswordHashScheme is the crypt scheme of the hash, e.g. sha512; salt-bootstrap always writes sha512, so another
	// one means the password was set some other way, e.g. by passwd with yescrypt
	PasswordHashScheme string `json:"passwordHashScheme,omitempty"`
	// PasswordCheck compares the request's saltUserPassword with the hash: match, mismatch or unverifiable (a scheme
	// other than sha512); it is missing when the request has no password
	PasswordCheck string `json:"passwordCheck,omitempty"`
	Error         string `json:"error,omitempty"`
}

type FileDiagnostics struct {
	Path string `json:"path"`
	// Mode is the permission bits in octal, e.g. "0640"
	Mode  string `json:"mode,omitempty"`
	Uid   *int   `json:"uid,omitempty"`
	Gid   *int   `json:"gid,omitempty"`
	Error string `json:"error,omitempty"`
}

// HostDiagnostics shows how the node sees its own name, to spot a hostname that does not match the minion id or an
// FQDN that does not resolve.
type HostDiagnostics struct {
	Hostname    string `json:"hostname,omitempty"`
	Fqdn        string `json:"fqdn,omitempty"`
	EtcHostname string `json:"etcHostname,omitempty"`
	// FqdnAddresses is what the resolver returns for Fqdn
	FqdnAddresses []string `json:"fqdnAddresses,omitempty"`
	FqdnError     string   `json:"fqdnError,omitempty"`
	// Addresses are the non-loopback addresses of the network interfaces
	Addresses     []string `json:"addresses,omitempty"`
	Nameservers   []string `json:"nameservers,omitempty"`
	SearchDomains []string `json:"searchDomains,omitempty"`
	// HostsEntries are the lines of /etc/hosts that mention Hostname or Fqdn
	HostsEntries                []string `json:"hostsEntries,omitempty"`
	HostsMissingTrailingNewline bool     `json:"hostsMissingTrailingNewline"`
	Error                       string   `json:"error,omitempty"`
}

// SaltJobsDiagnostics lists the salt jobs that have a proc file, i.e. that are running or were left behind by a
// killed process. A salt-minion that is stuck on a job, or a salt-master whose workers are all busy, shows up here
// before anything else does.
type SaltJobsDiagnostics struct {
	MinionJobs []SaltJobDiagnostics `json:"minionJobs,omitempty"`
	// the job lists keep the oldest jobs; the omitted ones are the newest
	MinionJobsOmitted int `json:"minionJobsOmitted,omitempty"`
	// MasterJobs is only present on nodes that have the salt-master proc directory
	MasterJobs        []SaltJobDiagnostics `json:"masterJobs,omitempty"`
	MasterJobsOmitted int                  `json:"masterJobsOmitted,omitempty"`
	// WorkerThreads is worker_threads of the salt-master configuration; it is nil when the configuration has none
	WorkerThreads *int   `json:"workerThreads,omitempty"`
	Error         string `json:"error,omitempty"`
}

type SaltJobDiagnostics struct {
	Jid string `json:"jid"`
	// StartedAt (RFC3339) and AgeSeconds are missing when the name of the proc file is no job id
	StartedAt  string `json:"startedAt,omitempty"`
	AgeSeconds *int64 `json:"ageSeconds,omitempty"`
}

type LogDiagnostics struct {
	Path      string   `json:"path"`
	Lines     []string `json:"lines"`
	Truncated bool     `json:"truncated,omitempty"`
	Error     string   `json:"error,omitempty"`
}

func (r DiagnosticsResponse) String() string {
	j, _ := json.Marshal(r)
	return fmt.Sprintf("DiagnosticsResponse: %s", string(j))
}

func (d NodeDiagnostics) WriteHttp(w http.ResponseWriter) NodeDiagnostics {
	if d.StatusCode == 0 {
		d.StatusCode = http.StatusOK
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(d.StatusCode)
	if err := json.NewEncoder(w).Encode(d); err != nil {
		log.Printf("[NodeDiagnostics.WriteHttp] [ERROR] failed to create json from model: %s", err.Error())
	}
	return d
}

func (r DiagnosticsResponse) WriteHttp(w http.ResponseWriter) DiagnosticsResponse {
	w.Header().Set("Content-Type", "application/json")
	if r.StatusCode != 0 {
		w.WriteHeader(r.StatusCode)
	}
	if err := json.NewEncoder(w).Encode(r); err != nil {
		log.Printf("[DiagnosticsResponse.WriteHttp] [ERROR] failed to create json from model: %s", err.Error())
	}
	return r
}

// decodeDiagnosticsRequest accepts an empty body, so the per-node route can be called without any payload.
func decodeDiagnosticsRequest(req *http.Request) (DiagnosticsRequest, error) {
	var request DiagnosticsRequest
	if err := json.NewDecoder(req.Body).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
		return request, err
	}
	return request, nil
}

func (r DiagnosticsRequest) logLines() int {
	if r.LogLines == nil {
		return diagConfig().DefaultLogLines
	}
	return max(0, min(*r.LogLines, diagConfig().MaxLogLines))
}

// validate rejects a request whose probeDeadline is no positive duration. Invalid additional units do not fail the
// request, see selectAdditionalUnits.
func (r DiagnosticsRequest) validate() error {
	_, err := r.probeDeadline()
	return err
}

// probeDeadline returns the deadline the request asks for, or the configured one when it asks for none.
func (r DiagnosticsRequest) probeDeadline() (time.Duration, error) {
	if r.ProbeDeadline == "" {
		return diagConfig().ProbeDeadline, nil
	}
	deadline, err := time.ParseDuration(r.ProbeDeadline)
	if err != nil {
		return 0, fmt.Errorf("invalid probeDeadline %q: %s", capLine(r.ProbeDeadline), err.Error())
	}
	if deadline <= 0 {
		return 0, fmt.Errorf("probeDeadline must be positive, got %s", r.ProbeDeadline)
	}
	return deadline, nil
}

// effectiveProbeDeadline is the deadline a node collects with. The handlers reject an invalid one, so only a direct
// caller can get the configured deadline in its place.
func (r DiagnosticsRequest) effectiveProbeDeadline() time.Duration {
	deadline, err := r.probeDeadline()
	if err != nil {
		return diagConfig().ProbeDeadline
	}
	return deadline
}

// selectAdditionalUnits splits the requested units into the ones to probe and the rejected ones, each reported with
// the reason. The names are passed as arguments to systemctl, so only plain systemd unit names are probed: a leading
// '-' (an option) and glob characters are not allowed. Duplicates count once; salt units are probed anyway, so they
// count against no limit. The units beyond maxAdditionalUnits are rejected in the order of the request. A unit is
// probed and reported by its canonicalUnitName, so "nginx" and "nginx.service" are one unit.
func (r DiagnosticsRequest) selectAdditionalUnits() (probed []string, rejected []UnitDiagnostics) {
	config := diagConfig()
	var seen []string
	accepted := 0
	for _, requested := range r.AdditionalUnits {
		name := canonicalUnitName(requested)
		if slices.Contains(seen, name) {
			continue
		}
		seen = append(seen, name)
		switch {
		case len(requested) > config.MaxUnitNameLength || !diagnosticsUnitNamePattern.MatchString(requested):
			rejected = append(rejected, UnitDiagnostics{Name: capLine(requested), Rejected: fmt.Sprintf(
				"not a plain systemd unit name of at most %d characters (%s)", config.MaxUnitNameLength, diagnosticsUnitNamePattern)})
		case isSaltUnit(name):
			probed = append(probed, name)
		case accepted >= config.MaxAdditionalUnits:
			rejected = append(rejected, UnitDiagnostics{Name: requested, Rejected: fmt.Sprintf(
				"more than %d additional units requested", config.MaxAdditionalUnits)})
		default:
			accepted++
			probed = append(probed, name)
		}
	}
	return probed, rejected
}

func DiagnosticsHandler(w http.ResponseWriter, req *http.Request) {
	// nothing is logged before the logs are collected, so the saltboot.log tail is not this request's own output
	request, err := decodeDiagnosticsRequest(req)
	if err != nil {
		log.Printf("[DiagnosticsHandler] [ERROR] couldn't decode json: %s", err.Error())
		NodeDiagnostics{StatusCode: http.StatusBadRequest, ErrorText: err.Error()}.WriteHttp(w)
		return
	}
	if err := request.validate(); err != nil {
		log.Printf("[DiagnosticsHandler] [ERROR] invalid request: %s", err.Error())
		NodeDiagnostics{StatusCode: http.StatusBadRequest, ErrorText: err.Error()}.WriteHttp(w)
		return
	}

	baseDir := req.Header.Get("salt-minion-base-dir")
	diagnostics := collectDiagnostics(baseDir, request)
	diagnostics.WriteHttp(w)
	log.Printf("[DiagnosticsHandler] node diagnostics collected, timed out probes: %s", diagnostics.TimedOutProbes)
}

func DiagnosticsDistributeHandler(w http.ResponseWriter, req *http.Request) {
	log.Println("[DiagnosticsDistributeHandler] distribute diagnostics request")

	request, err := decodeDiagnosticsRequest(req)
	if err != nil {
		log.Printf("[DiagnosticsDistributeHandler] [ERROR] couldn't decode json: %s", err.Error())
		DiagnosticsResponse{StatusCode: http.StatusBadRequest, ErrorText: err.Error()}.WriteHttp(w)
		return
	}
	if err := request.validate(); err != nil {
		log.Printf("[DiagnosticsDistributeHandler] [ERROR] invalid request: %s", err.Error())
		DiagnosticsResponse{StatusCode: http.StatusBadRequest, ErrorText: err.Error()}.WriteHttp(w)
		return
	}
	// a node still collecting when the fan-out stops waiting would look unreachable
	if deadline, _ := request.probeDeadline(); request.ProbeDeadline != "" && !deadlineLeavesMargin(deadline, diagConfig().DistributeTimeout) {
		text := fmt.Sprintf("probeDeadline %s leaves less than %s of the distributeTimeout %s of this node for the response", deadline,
			diagnosticsResponseMargin, diagConfig().DistributeTimeout)
		log.Printf("[DiagnosticsDistributeHandler] [ERROR] invalid request: %s", text)
		DiagnosticsResponse{StatusCode: http.StatusBadRequest, ErrorText: text}.WriteHttp(w)
		return
	}
	if len(request.Targets) == 0 {
		log.Printf("[DiagnosticsDistributeHandler] [ERROR] no targets were specified in the request")
		DiagnosticsResponse{StatusCode: http.StatusBadRequest, ErrorText: "no targets were specified in the request"}.WriteHttp(w)
		return
	}

	user, pass := GetAuthUserPass(req)
	signedRequestBody := GetSignedRequestBody(req)

	log.Printf("[DiagnosticsDistributeHandler] send diagnostics request to nodes: %s", request.Targets)
	nodes := distributeDiagnosticsImpl(DistributeRawRequest, request.Targets, user, pass, signedRequestBody,
		diagConfig().DistributeTimeout, diagConfig().MaxParallelTargets)
	DiagnosticsResponse{Nodes: nodes, Checks: safeDiagnosticsChecks(nodes, request.AdditionalUnits),
		ConfigFingerprint: diagConfig().fingerprint(), ConfigError: diagConfig().loadError}.WriteHttp(w)
	// the full response holds log lines, so only the per-node outcome is logged here
	for _, node := range nodes {
		log.Printf("[DiagnosticsDistributeHandler] node: %s, status code: %d, error: %s", node.Address, node.StatusCode, node.ErrorText)
	}
}

func distributeDiagnosticsImpl(distribute func([]string, string, string, string, RequestBody, time.Duration, int) <-chan RawResponse,
	targets []string, user string, pass string, requestBody RequestBody, timeout time.Duration, maxParallel int) []NodeDiagnostics {
	var responses []RawResponse
	for raw := range distribute(targets, DiagnosticsEP, user, pass, requestBody, timeout, maxParallel) {
		responses = append(responses, raw)
	}
	var first time.Time
	for _, raw := range responses {
		if !raw.ContactedAt.IsZero() && (first.IsZero() || raw.ContactedAt.Before(first)) {
			first = raw.ContactedAt
		}
	}
	nodes := make([]NodeDiagnostics, 0, len(responses))
	for _, raw := range responses {
		node := toNodeDiagnostics(raw)
		if !raw.ContactedAt.IsZero() {
			node.contactOffset = raw.ContactedAt.Sub(first)
		}
		nodes = append(nodes, node)
	}
	return nodes
}

// toNodeDiagnostics keeps the transport outcome visible: an unreachable node or one running an older
// salt-bootstrap without this route (404) still gets an entry with its address, status code and error.
func toNodeDiagnostics(raw RawResponse) NodeDiagnostics {
	if raw.Err != nil {
		return NodeDiagnostics{Address: raw.Address, StatusCode: http.StatusInternalServerError, ErrorText: raw.Err.Error()}
	}
	var node NodeDiagnostics
	if err := json.Unmarshal(raw.Body, &node); err != nil {
		statusCode := raw.StatusCode
		if statusCode < 300 {
			statusCode = http.StatusInternalServerError
		}
		return NodeDiagnostics{Address: raw.Address, StatusCode: statusCode,
			ErrorText: fmt.Sprintf("unexpected response: %s", capLine(strings.TrimSpace(string(raw.Body))))}
	}
	node.Address = raw.Address
	if node.StatusCode == 0 {
		node.StatusCode = raw.StatusCode
	}
	return node
}

type diagnosticsProbe struct {
	name string
	run  func() func(*NodeDiagnostics)
}

// collectDiagnostics first reads the logs, because every other probe logs to saltboot.log and would push the
// lines that matter out of its tail. It then runs the remaining probes concurrently and returns whatever
// finished within the probe deadline, so a hung command never keeps the node from answering before the
// fan-out timeout. Each probe hands back a
// setter instead of writing the result itself, so a probe that finishes late cannot race with the response.
func collectDiagnostics(baseDir string, request DiagnosticsRequest) NodeDiagnostics {
	return collectDiagnosticsWith(baseDir, request, diagnosticsProbes(baseDir, request))
}

func diagnosticsProbes(baseDir string, request DiagnosticsRequest) []diagnosticsProbe {
	timeouts := diagConfig().timeoutsWithin(request.effectiveProbeDeadline())
	return []diagnosticsProbe{
		{"units", func() func(*NodeDiagnostics) {
			probed, rejected := request.selectAdditionalUnits()
			units := append(probeUnits(baseDir, probed, timeouts), rejected...)
			slices.SortStableFunc(units, func(a, b UnitDiagnostics) int { return strings.Compare(a.Name, b.Name) })
			return func(d *NodeDiagnostics) { d.Units = units }
		}},
		{"minion", func() func(*NodeDiagnostics) {
			minion := probeMinion(baseDir)
			probeMasterPorts(minion.Masters, timeouts)
			return func(d *NodeDiagnostics) { d.setMinion(minion) }
		}},
		{"time", func() func(*NodeDiagnostics) {
			t := probeTime(timeouts)
			return func(d *NodeDiagnostics) { d.Time = &t }
		}},
		{"resources", func() func(*NodeDiagnostics) {
			load, memory, root := probeLoad(baseDir), probeMemory(baseDir), probeRootFilesystem(baseDir)
			bootTime, bootTimeErr := probeBootTime(baseDir)
			mounts, mountsErr := probeMounts(baseDir)
			return func(d *NodeDiagnostics) {
				d.setLoadMemoryAndRoot(&load, &memory, &root)
				d.setBootTimeAndMounts(bootTime, bootTimeErr, mounts, mountsErr)
			}
		}},
		{"master", func() func(*NodeDiagnostics) {
			master := probeMaster(baseDir)
			return func(d *NodeDiagnostics) { d.setMaster(master) }
		}},
		// separate from resources, so a hanging lvs cannot take load, memory and disk with it
		{"lvm", func() func(*NodeDiagnostics) {
			lvm := probeLvm(baseDir, timeouts)
			return func(d *NodeDiagnostics) { d.setLvm(lvm) }
		}},
		{"saltUser", func() func(*NodeDiagnostics) {
			saltUser := probeSaltUser(baseDir, timeouts, request.SaltUserPassword)
			return func(d *NodeDiagnostics) { d.SaltUser = saltUser }
		}},
		// separate from the others, so a hanging resolver or hostname command only takes the host section with it
		{"host", func() func(*NodeDiagnostics) {
			host := probeHost(baseDir, timeouts)
			return func(d *NodeDiagnostics) { d.Host = &host }
		}},
		// separate from the minion probe, because it runs salt-call when it finds no version on disk
		{"saltVersion", func() func(*NodeDiagnostics) {
			minion, master := probeSaltVersions(baseDir, timeouts)
			return func(d *NodeDiagnostics) { d.setSaltVersions(minion, master) }
		}},
		// reads files only, so it neither needs nor waits for a salt command
		{"jobs", func() func(*NodeDiagnostics) {
			jobs := probeJobs(baseDir)
			return func(d *NodeDiagnostics) { d.Jobs = &jobs }
		}},
	}
}

// diagnosticsResponseMargin is what a node needs of the distributeTimeout after its probe deadline to send the response.
const diagnosticsResponseMargin = time.Second

// deadlineLeavesMargin tells whether a node collecting for deadline still answers within distributeTimeout.
func deadlineLeavesMargin(deadline, distributeTimeout time.Duration) bool {
	return deadline+diagnosticsResponseMargin <= distributeTimeout
}

func collectDiagnosticsWith(baseDir string, request DiagnosticsRequest, probes []diagnosticsProbe) NodeDiagnostics {
	config := diagConfig()
	probeDeadline := request.effectiveProbeDeadline()
	diagnostics := NodeDiagnostics{StatusCode: http.StatusOK, Version: Version + "-" + BuildTime,
		ConfigFingerprint: config.fingerprint(), ConfigError: config.loadError, ProbeDeadline: probeDeadline.String()}
	// started before the logs, so the deadline is the whole budget of the node
	deadline := time.After(probeDeadline)
	if logLines := request.logLines(); logLines > 0 {
		diagnostics.collectLogs(baseDir, logLines)
	}

	results := make(chan probeResult, len(probes))
	for _, probe := range probes {
		go func(probe diagnosticsProbe) {
			results <- runProbe(probe)
		}(probe)
	}

	pending := make(map[string]bool, len(probes))
	for _, probe := range probes {
		pending[probe.name] = true
	}
	for len(pending) > 0 {
		select {
		case result := <-results:
			diagnostics.applyProbe(result)
			delete(pending, result.name)
		case <-deadline:
			for _, probe := range probes {
				if pending[probe.name] {
					diagnostics.TimedOutProbes = append(diagnostics.TimedOutProbes, probe.name)
				}
			}
			log.Printf("[collectDiagnostics] [WARN] probes timed out: %s", diagnostics.TimedOutProbes)
			slices.Sort(diagnostics.FailedProbes)
			return diagnostics
		}
	}
	slices.Sort(diagnostics.FailedProbes)
	return diagnostics
}

// probeResult is what a probe hands back: the setter, or in failed the panic of the probe.
type probeResult struct {
	name   string
	apply  func(*NodeDiagnostics)
	failed string
}

// runProbe turns a panic of the probe into a result, so it neither crashes the process nor stays pending.
func runProbe(probe diagnosticsProbe) (result probeResult) {
	defer func() {
		if r := recover(); r != nil {
			result = probeResult{name: probe.name, failed: probeFailure(probe.name, r)}
		}
	}()
	return probeResult{name: probe.name, apply: probe.run()}
}

// applyProbe runs the setter of a finished probe; a panic in it is recorded like a panic in the probe.
func (d *NodeDiagnostics) applyProbe(result probeResult) {
	defer func() {
		if r := recover(); r != nil {
			d.FailedProbes = append(d.FailedProbes, probeFailure(result.name, r))
		}
	}()
	if result.failed != "" {
		d.FailedProbes = append(d.FailedProbes, result.failed)
		return
	}
	result.apply(d)
}

// collectLogs is guarded like a probe, as it runs before them.
func (d *NodeDiagnostics) collectLogs(baseDir string, lines int) {
	defer func() {
		if r := recover(); r != nil {
			d.FailedProbes = append(d.FailedProbes, probeFailure("logs", r))
		}
	}()
	d.Logs = readLogs(baseDir, lines)
}

// readLogs is replaced in tests.
var readLogs = probeLogs

// probeGroup runs functions in goroutines of their own like a sync.WaitGroup. A panic would crash the whole process
// in a goroutine nobody recovers, so it is captured and Wait panics with the first one in the probe's goroutine,
// where runProbe records it.
type probeGroup struct {
	wg       sync.WaitGroup
	mu       sync.Mutex
	panicked bool
	value    any
}

func (g *probeGroup) Go(fn func()) {
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[collectDiagnostics] [ERROR] goroutine of a probe panicked: %v\n%s", r, debug.Stack())
				g.mu.Lock()
				defer g.mu.Unlock()
				if !g.panicked {
					g.panicked, g.value = true, r
				}
			}
		}()
		fn()
	}()
}

func (g *probeGroup) Wait() {
	g.wg.Wait()
	if g.panicked {
		panic(g.value)
	}
}

// probeFailure logs the panic of a probe with its stack and returns the text for FailedProbes.
func probeFailure(name string, panicValue any) string {
	log.Printf("[collectDiagnostics] [ERROR] probe %s panicked: %v\n%s", name, panicValue, debug.Stack())
	return fmt.Sprintf("%s: %v", name, panicValue)
}

// probeUnits reports the built-in units and the requested ones the same way. Unlike an optional built-in unit, a
// requested unit is reported even when it does not exist, because the caller asked for it.
func probeUnits(baseDir string, requested []string, timeouts probeTimeouts) []UnitDiagnostics {
	if GetInitSystem().ActionBin != SYSTEM_D.ActionBin {
		return []UnitDiagnostics{{Name: "salt-minion", Error: "unsupported init system"}}
	}
	required := maps.Clone(diagConfig().Units)
	for _, name := range requested {
		required[name] = true
	}
	// sorted, so the order is stable from call to call
	names := slices.Sorted(maps.Keys(required))
	// one systemctl per unit in parallel, as a slow systemd would need n times the command timeout one after another
	probed := make([]UnitDiagnostics, len(names))
	var group probeGroup
	for i, name := range names {
		group.Go(func() {
			probed[i] = probeUnit(name, timeouts)
			if pid := probed[i].MainPid; pid != nil && *pid > 0 {
				probed[i].Process = probeProcess(baseDir, *pid)
			}
		})
	}
	group.Wait()
	units := make([]UnitDiagnostics, 0, len(names))
	for i, unit := range probed {
		if !required[names[i]] && unit.LoadState == "not-found" {
			continue
		}
		units = append(units, unit)
	}
	return units
}

// probeUnit has a timeout, as systemctl blocks when systemd or dbus hangs, a failure diagnostics must survive.
func probeUnit(name string, timeouts probeTimeouts) UnitDiagnostics {
	unit := UnitDiagnostics{Name: name}
	out, err := ExecCmdWithTimeout(timeouts.command, SYSTEM_D.StateBin, "show", name, "--no-pager",
		"-p", "LoadState", "-p", "ActiveState", "-p", "SubState", "-p", "ActiveEnterTimestamp", "-p", "NRestarts", "-p", "MainPID")
	if err != nil {
		unit.Error = strings.TrimSpace(out + " " + err.Error())
		return unit
	}
	props := parseKeyValueLines(out, "=")
	unit.LoadState = props["LoadState"]
	unit.ActiveState = props["ActiveState"]
	unit.SubState = props["SubState"]
	unit.ActiveEnterTimestamp = props["ActiveEnterTimestamp"]
	// NRestarts is missing on systemd older than 235, so it stays nil there instead of reading as 0
	unit.NRestarts = parseOptionalInt(props["NRestarts"])
	unit.MainPid = parseOptionalInt(props["MainPID"])
	return unit
}

// probeProcess reads the state, memory, threads, open file descriptors and uptime of a process from /proc.
func probeProcess(baseDir string, pid int) *ProcessDiagnostics {
	var process ProcessDiagnostics
	var errs []string
	procDir := baseDir + "/proc/" + strconv.Itoa(pid)

	if b, err := os.ReadFile(procDir + "/status"); err != nil {
		errs = append(errs, "status: "+err.Error())
	} else {
		status := parseKeyValueLines(string(b), ":")
		process.State = status["State"]
		process.RssKb = parseOptionalKb(status["VmRSS"])
		process.Threads = parseOptionalInt(status["Threads"])
	}

	if fds, err := os.ReadDir(procDir + "/fd"); err != nil {
		errs = append(errs, "fd: "+err.Error())
	} else {
		count := len(fds)
		process.OpenFds = &count
	}

	if uptime, err := processUptimeSeconds(baseDir, procDir); err != nil {
		errs = append(errs, "uptime: "+err.Error())
	} else {
		process.UptimeSeconds = &uptime
	}

	process.Error = strings.Join(errs, "; ")
	return &process
}

// processUptimeSeconds subtracts the process start time in /proc/<pid>/stat from the system uptime in /proc/uptime.
func processUptimeSeconds(baseDir, procDir string) (int64, error) {
	stat, err := os.ReadFile(procDir + "/stat")
	if err != nil {
		return 0, err
	}
	// the command name in field 2 may contain spaces and parentheses, so the fields are counted from its closing ')'
	end := strings.LastIndex(string(stat), ")")
	if end < 0 {
		return 0, errors.New("unexpected stat format")
	}
	fields := strings.Fields(string(stat)[end+1:])
	// starttime is field 22 of stat, i.e. the 20th after the command name
	if len(fields) < 20 {
		return 0, errors.New("unexpected stat format")
	}
	startTicks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, err
	}
	uptime, err := os.ReadFile(baseDir + "/proc/uptime")
	if err != nil {
		return 0, err
	}
	uptimeFields := strings.Fields(string(uptime))
	if len(uptimeFields) == 0 {
		return 0, errors.New("unexpected uptime format")
	}
	systemUptime, err := strconv.ParseFloat(uptimeFields[0], 64)
	if err != nil {
		return 0, err
	}
	// the kernel reports starttime in USER_HZ ticks, which is 100 on x86_64 and arm64
	return int64(systemUptime - float64(startTicks)/100), nil
}

func probeMinion(baseDir string) MinionDiagnostics {
	var minion MinionDiagnostics
	var errs []string

	masters, found, err := readSaltMasterList(baseDir + "/etc/salt/minion.d/master.conf")
	if err != nil {
		errs = append(errs, "master.conf: "+err.Error())
	} else if !found {
		errs = append(errs, "master.conf: missing or empty")
	}
	for _, master := range masters {
		minion.Masters = append(minion.Masters, MinionMasterDiagnostics{Id: master})
	}

	if b, err := os.ReadFile(baseDir + "/etc/salt/minion.d/minion_id.conf"); err == nil {
		var idConf map[string]string
		if err := yaml.Unmarshal(b, &idConf); err != nil {
			errs = append(errs, "minion_id.conf: "+err.Error())
		} else {
			minion.IdConfig = idConf["id"]
		}
	} else if !os.IsNotExist(err) {
		errs = append(errs, "minion_id.conf: "+err.Error())
	}

	if b, err := os.ReadFile(baseDir + "/etc/salt/minion_id"); err == nil {
		minion.CachedId = strings.TrimSpace(string(b))
	} else if !os.IsNotExist(err) {
		errs = append(errs, "minion_id: "+err.Error())
	}

	fingerprint := getMinionFingerprintFromPrivateKeyAt(baseDir + MinionKey)
	if fingerprint.ErrorText != "" {
		errs = append(errs, "fingerprint: "+fingerprint.ErrorText)
	} else {
		minion.Fingerprint = fingerprint.Status
	}

	pkiDir := baseDir + "/etc/salt/pki/minion"
	masterKey, found, err := readKeyFingerprint(pkiDir + "/minion_master.pub")
	if err != nil {
		errs = append(errs, "minion_master.pub: "+err.Error())
	} else if !found {
		errs = append(errs, "minion_master.pub: missing")
	}
	minion.MasterKeyFingerprint = masterKey
	// master_sign.pub only exists when the salt-master signs its key
	signKey, found, err := readKeyFingerprint(pkiDir + "/master_sign.pub")
	if err != nil {
		errs = append(errs, "master_sign.pub: "+err.Error())
	}
	minion.MasterSignKeyFingerprint = signKey

	minion.Error = strings.Join(errs, "; ")
	return minion
}

// readKeyFingerprint returns the fingerprint of the public key file in the format of the other fingerprints, so
// they are comparable. found is false when the file does not exist.
func readKeyFingerprint(path string) (fingerprint string, found bool, err error) {
	key, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "", false, nil
	}
	if err != nil {
		return "", true, err
	}
	fingerprint, err = getFingerprintOfPublicKeyPem(key)
	return fingerprint, true, err
}

// probeMasterPorts checks every port of every master concurrently and stores the results on the masters.
func probeMasterPorts(masters []MinionMasterDiagnostics, timeouts probeTimeouts) {
	var group probeGroup
	for i := range masters {
		masters[i].Ports = make([]PortDiagnostics, len(diagConfig().MasterPorts))
		for j, port := range diagConfig().MasterPorts {
			result, master := &masters[i].Ports[j], masters[i].Id
			group.Go(func() { *result = probePort(master, port, timeouts.dial) })
		}
	}
	group.Wait()
}

func probePort(master string, port int, timeout time.Duration) PortDiagnostics {
	result := PortDiagnostics{Port: port}
	start := time.Now()
	conn, err := dialTimeout("tcp", net.JoinHostPort(master, strconv.Itoa(port)), timeout)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	closeIt(conn)
	result.Reachable = true
	result.LatencyMs = time.Since(start).Milliseconds()
	return result
}

// probeMaster lists the minion keys in the salt-master's pki directory with their key state. It reads the key
// files only and runs no salt command, so it works even when salt-master itself is down or overloaded. Nodes
// without a salt-master pki directory get no master section.
func probeMaster(baseDir string) *MasterDiagnostics {
	pkiDir := baseDir + "/etc/salt/pki/master"
	if _, err := os.Stat(pkiDir); os.IsNotExist(err) {
		return nil
	}

	master := MasterDiagnostics{Minions: []MasterMinionDiagnostics{}}
	var errs []string
	var err error
	if master.KeyFingerprint, _, err = readKeyFingerprint(pkiDir + "/master.pub"); err != nil {
		errs = append(errs, "master.pub: "+err.Error())
	}
	if master.SignKeyFingerprint, _, err = readKeyFingerprint(pkiDir + "/master_sign.pub"); err != nil {
		errs = append(errs, "master_sign.pub: "+err.Error())
	}
	for _, keyDir := range diagnosticsMasterKeyDirs {
		entries, err := os.ReadDir(pkiDir + "/" + keyDir.dir)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			errs = append(errs, keyDir.dir+": "+err.Error())
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			minion := MasterMinionDiagnostics{Id: entry.Name(), KeyState: keyDir.state}
			if keyDir.state == "accepted" {
				key, err := os.ReadFile(pkiDir + "/" + keyDir.dir + "/" + entry.Name())
				if err == nil {
					minion.Fingerprint, err = getFingerprintOfPublicKeyPem(key)
				}
				if err != nil {
					minion.Error = "fingerprint: " + err.Error()
				}
			}
			master.Minions = append(master.Minions, minion)
		}
	}
	slices.SortStableFunc(master.Minions, func(a, b MasterMinionDiagnostics) int { return strings.Compare(a.Id, b.Id) })
	master.Error = strings.Join(errs, "; ")
	return &master
}

// probeSaltUser reports the state of the saltuser account from /etc/shadow and /etc/passwd without ever
// returning the password hash. Nodes with no saltuser entry that are no salt-master get no saltUser section.
func probeSaltUser(baseDir string, timeouts probeTimeouts, expectedPassword string) *SaltUserDiagnostics {
	shadow, shadowErr := os.ReadFile(baseDir + SHADOW_FILE)
	entry, found := findAccountEntry(string(shadow), SALT_USER)
	_, pkiErr := os.Stat(baseDir + "/etc/salt/pki/master")
	isMaster := pkiErr == nil
	// an unreadable /etc/shadow is reported, as the entry may be in it
	if !found && !isMaster && (shadowErr == nil || os.IsNotExist(shadowErr)) {
		return nil
	}

	var saltUser SaltUserDiagnostics
	var errs []string
	if shadowErr != nil {
		errs = append(errs, "shadow: "+shadowErr.Error())
	}
	if found {
		parseShadowEntry(entry, diagnosticsNow(), &saltUser)
		hash := shadowHash(entry)
		saltUser.PasswordHashScheme = passwordHashScheme(hash)
		if expectedPassword != "" {
			saltUser.PasswordCheck = checkShadowPassword(hash, expectedPassword)
		}
	}

	if passwd, err := os.ReadFile(baseDir + "/etc/passwd"); err == nil {
		_, saltUser.PasswdEntry = findAccountEntry(string(passwd), SALT_USER)
	} else if !os.IsNotExist(err) {
		errs = append(errs, "passwd: "+err.Error())
	}
	_, newErr := os.Stat(baseDir + SHADOW_FILE_NEW)
	saltUser.ShadowNewLeftover = newErr == nil

	for _, path := range diagnosticsAccountFiles {
		saltUser.Files = append(saltUser.Files, probeFile(baseDir, path))
	}

	if faillock := findTool("faillock"); faillock != "" {
		failures, err := probeFaillock(faillock, timeouts)
		if err != nil {
			errs = append(errs, "faillock: "+err.Error())
		}
		saltUser.FaillockFailures = failures
	}

	saltUser.Error = strings.Join(errs, "; ")
	return &saltUser
}

// shadowHash returns the hash field of a shadow line without the '!' a lock puts in front of it.
func shadowHash(entry string) string {
	fields := strings.SplitN(entry, ":", 3)
	if len(fields) < 2 {
		return ""
	}
	return strings.TrimLeft(fields[1], "!")
}

// passwordHashScheme names the crypt scheme of a shadow hash by its prefix.
func passwordHashScheme(hash string) string {
	for prefix, scheme := range map[string]string{"$6$": "sha512", "$5$": "sha256", "$1$": "md5", "$y$": "yescrypt",
		"$gy$": "gost-yescrypt", "$7$": "scrypt", "$2a$": "bcrypt", "$2b$": "bcrypt", "$2y$": "bcrypt"} {
		if strings.HasPrefix(hash, prefix) {
			return scheme
		}
	}
	switch {
	case hash == "":
		return "none"
	case strings.HasPrefix(hash, "*"):
		// no password at all, e.g. "*" or "*LK*"
		return "none"
	case !strings.HasPrefix(hash, "$"):
		return "des"
	}
	return "unknown"
}

// checkShadowPassword tells whether password produces hash. Only sha512 can be checked, the scheme salt-bootstrap
// writes; the comparison takes the same time whatever the hash, so it says nothing about how close a guess was.
func checkShadowPassword(hash, password string) string {
	if passwordHashScheme(hash) != "sha512" {
		return "unverifiable"
	}
	// the salt, and the rounds if any, are read from the hash itself
	computed, err := generatePasswordHashWithSalt(password, hash)
	if err != nil {
		return "unverifiable"
	}
	if subtle.ConstantTimeCompare([]byte(computed), []byte(hash)) == 1 {
		return "match"
	}
	return "mismatch"
}

// findAccountEntry returns the line of the account in a passwd or shadow style file.
func findAccountEntry(content, account string) (string, bool) {
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, account+":") {
			return line, true
		}
	}
	return "", false
}

// parseShadowEntry fills the account state from a shadow line (name:hash:lastchange:min:max:warn:inactive:expire).
// Only what the hash says about the account is kept, never the hash itself. The password is expired the day after
// lastchange+max, which is when pam_unix starts to demand a new one, and the account is expired from its expire day.
func parseShadowEntry(entry string, now time.Time, saltUser *SaltUserDiagnostics) {
	fields := strings.Split(entry, ":")
	for len(fields) < 9 {
		fields = append(fields, "")
	}
	today := int(now.UTC().Unix() / secondsPerDay)

	saltUser.Present = true
	saltUser.Locked = strings.HasPrefix(fields[1], "!") || strings.HasPrefix(fields[1], "*")
	saltUser.EmptyPassword = fields[1] == ""
	lastChange := parseOptionalInt(fields[2])
	saltUser.MinDays = parseOptionalInt(fields[3])
	saltUser.MaxDays = parseOptionalInt(fields[4])
	saltUser.WarnDays = parseOptionalInt(fields[5])
	saltUser.InactiveDays = parseOptionalInt(fields[6])

	if lastChange != nil && *lastChange == 0 {
		saltUser.PasswordChangeRequired = true
	} else if lastChange != nil && *lastChange > 0 {
		saltUser.LastChange = shadowDate(*lastChange)
		if maxDays := saltUser.MaxDays; maxDays != nil && *maxDays >= 0 && *maxDays < shadowNoExpiryDays {
			expiry := *lastChange + *maxDays
			daysLeft := expiry - today
			saltUser.PasswordExpiresAt = shadowDate(expiry)
			saltUser.DaysUntilPasswordExpiry = &daysLeft
			saltUser.PasswordExpired = daysLeft < 0
			if saltUser.InactiveDays != nil && *saltUser.InactiveDays >= 0 {
				saltUser.PasswordInactiveAt = shadowDate(expiry + *saltUser.InactiveDays)
			}
		}
	}

	if accountExpiry := parseOptionalInt(fields[7]); accountExpiry != nil && *accountExpiry >= 0 {
		saltUser.AccountExpiresAt = shadowDate(*accountExpiry)
		saltUser.AccountExpired = today >= *accountExpiry
	}
}

// shadowDate converts the days since the epoch /etc/shadow counts in to YYYY-MM-DD.
func shadowDate(days int) string {
	return time.Unix(int64(days)*secondsPerDay, 0).UTC().Format("2006-01-02")
}

// probeFile reports the permission bits and the owner of a file below baseDir.
func probeFile(baseDir, path string) FileDiagnostics {
	file := FileDiagnostics{Path: path}
	info, err := os.Stat(baseDir + path)
	if err != nil {
		file.Error = err.Error()
		return file
	}
	file.Mode = fmt.Sprintf("%04o", info.Mode().Perm())
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		uid, gid := int(st.Uid), int(st.Gid)
		file.Uid, file.Gid = &uid, &gid
	}
	return file
}

// probeFaillock counts the failed logins of saltuser faillock still holds. They lock the account out once their
// number reaches the deny limit of the PAM configuration. The tool prints a header line and one line per failure,
// ending in V while the failure is valid and in I once it is no longer counted.
func probeFaillock(faillock string, timeouts probeTimeouts) (*int, error) {
	out, err := ExecCmdWithTimeout(timeouts.command, faillock, "--user", SALT_USER)
	if err != nil {
		return nil, err
	}
	failures := 0
	for _, line := range strings.Split(out, "\n") {
		if fields := strings.Fields(line); len(fields) > 1 && fields[len(fields)-1] == "V" {
			failures++
		}
	}
	return &failures, nil
}

// probeHost shows how the node sees its own name. Every command has a timeout and the FQDN lookup has one as
// well, as a node with a broken resolver can hang for minutes in hostname -f.
func probeHost(baseDir string, timeouts probeTimeouts) HostDiagnostics {
	var host HostDiagnostics
	var errs []string

	var fqdn string
	var fqdnErr error
	var group probeGroup
	group.Go(func() { fqdn, fqdnErr = ExecCmdWithTimeout(timeouts.command, "hostname", "-f") })
	hostname, err := ExecCmdWithTimeout(timeouts.command, "hostname", "-s")
	if err != nil {
		hostname, err = ExecCmdWithTimeout(timeouts.command, "hostname")
	}
	group.Wait()
	if err != nil {
		errs = append(errs, "hostname: "+err.Error())
	} else {
		host.Hostname = hostname
	}
	if fqdnErr != nil {
		errs = append(errs, "fqdn: "+fqdnErr.Error())
	} else {
		host.Fqdn = fqdn
	}

	if host.Fqdn != "" {
		ctx, cancel := context.WithTimeout(context.Background(), timeouts.lookup)
		host.FqdnAddresses, err = lookupHost(ctx, host.Fqdn)
		cancel()
		if err != nil {
			host.FqdnError = err.Error()
		}
	}

	if b, err := os.ReadFile(baseDir + HOSTNAME_FILE); err == nil {
		host.EtcHostname = strings.TrimSpace(string(b))
	} else if !os.IsNotExist(err) {
		errs = append(errs, "hostname file: "+err.Error())
	}

	if addrs, err := interfaceAddrs(); err != nil {
		errs = append(errs, "addresses: "+err.Error())
	} else {
		host.Addresses = nonLoopbackAddresses(addrs)
	}

	if b, err := os.ReadFile(baseDir + "/etc/resolv.conf"); err != nil {
		errs = append(errs, "resolv.conf: "+err.Error())
	} else {
		host.Nameservers, host.SearchDomains = parseResolvConf(string(b))
	}

	if b, err := os.ReadFile(baseDir + HOSTS_FILE); err != nil {
		errs = append(errs, "hosts: "+err.Error())
	} else {
		host.HostsEntries = hostsEntriesFor(string(b), host.Hostname, host.Fqdn)
		host.HostsMissingTrailingNewline = len(b) > 0 && b[len(b)-1] != '\n'
	}

	host.Error = strings.Join(errs, "; ")
	return host
}

func nonLoopbackAddresses(addrs []net.Addr) []string {
	var result []string
	for _, addr := range addrs {
		var ip net.IP
		switch a := addr.(type) {
		case *net.IPNet:
			ip = a.IP
		case *net.IPAddr:
			ip = a.IP
		}
		if ip != nil && !ip.IsLoopback() {
			result = append(result, ip.String())
		}
	}
	return result
}

// parseResolvConf returns the nameservers and the search domains. As in glibc, the last search or domain line wins.
func parseResolvConf(content string) (nameservers, searchDomains []string) {
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "nameserver":
			nameservers = append(nameservers, fields[1])
		case "search", "domain":
			searchDomains = fields[1:]
		}
	}
	return nameservers, searchDomains
}

// hostsEntriesFor returns the trimmed lines of an /etc/hosts file that name one of the hosts. A name has to match
// as a whole, so node1 does not pick up node10.
func hostsEntriesFor(content string, hosts ...string) []string {
	var entries []string
	for _, line := range strings.Split(content, "\n") {
		entry, _, _ := strings.Cut(line, "#")
		fields := strings.Fields(entry)
		if len(fields) < 2 {
			continue
		}
		for _, name := range fields[1:] {
			if name != "" && slices.Contains(hosts, name) {
				entries = append(entries, strings.TrimSpace(line))
				break
			}
		}
	}
	return entries
}

// saltVersion is what the saltVersion probe finds out about one salt service.
type saltVersion struct {
	version, pythonVersion, installPath, err string
}

// probeSaltVersions finds the salt version of the salt-minion and, on salt-master nodes, of the salt-master. It
// asks systemd where the service is started from and reads the installed package's metadata from there; rpm and
// dpkg are not used, as rpm hangs on a corrupt database. master is nil on nodes with no salt-master.
func probeSaltVersions(baseDir string, timeouts probeTimeouts) (minion saltVersion, master *saltVersion) {
	if GetInitSystem().ActionBin != SYSTEM_D.ActionBin {
		return saltVersion{err: "unsupported init system"}, nil
	}
	var group probeGroup
	group.Go(func() {
		_, pkiErr := os.Stat(baseDir + "/etc/salt/pki/master")
		master = probeSaltServiceVersion(baseDir, "salt-master", pkiErr == nil, timeouts)
	})
	minion = *probeSaltServiceVersion(baseDir, "salt-minion", true, timeouts)
	group.Wait()
	return minion, master
}

// probeSaltServiceVersion returns nil for a service that does not exist, unless it is expected to, in which case
// the problem is reported.
//
// The first layout it expects is a relocatable salt install: the unit starts an executable
// like /opt/salt_<version>/bin/salt-minion, whose #! line names the bundled python, and the salt package is in
// <prefix>/lib/python3.X/site-packages (lib64 and dist-packages are tried as well). This is an assumption and
// should be verified on current images; salt-call --version next to the executable is the fallback.
// The salt 3006 onedir layout is understood as well: its units start /usr/bin/salt-minion, a symlink into
// /opt/saltstack/salt, whose scripts start with #!/bin/sh and whose package is in
// /opt/saltstack/salt/lib/python3.X/site-packages/salt/_version.txt.
func probeSaltServiceVersion(baseDir, unit string, expected bool, timeouts probeTimeouts) *saltVersion {
	out, err := ExecCmdWithTimeout(timeouts.command, SYSTEM_D.StateBin, "show", unit, "-p", "ExecStart")
	if err != nil {
		if !expected {
			return nil
		}
		return &saltVersion{err: "ExecStart: " + err.Error()}
	}
	execStart := parseKeyValueLines(out, "=")["ExecStart"]
	if execStart == "" {
		if !expected {
			return nil
		}
		return &saltVersion{err: unit + " has no ExecStart"}
	}
	executable := parseExecStartExecutable(execStart, unit)
	if executable == "" {
		return &saltVersion{err: "cannot find " + unit + " in ExecStart"}
	}

	// the unit can start a symlink, like /usr/bin/salt-minion pointing into /opt/saltstack/salt
	if resolved, err := filepath.EvalSymlinks(baseDir + executable); err == nil {
		root := baseDir
		if realRoot, err := filepath.EvalSymlinks(baseDir); err == nil {
			root = realRoot
		}
		if relative, ok := strings.CutPrefix(resolved, root); ok && strings.HasPrefix(relative, "/") {
			executable = relative
		}
	}

	executableDir := filepath.Dir(executable)
	interpreter := readShebangInterpreter(baseDir + executable)
	prefixes := []string{installPrefix(executableDir)}
	if interpreter != "" {
		prefixes = slices.Insert(prefixes, 0, installPrefix(filepath.Dir(interpreter)))
	}
	prefixes = slices.Compact(prefixes)

	result := saltVersion{installPath: prefixes[0]}
	for _, prefix := range prefixes {
		version, pythonVersion := findInstalledSaltVersion(baseDir + prefix)
		if version != "" {
			result.version, result.pythonVersion, result.installPath = version, pythonVersion, prefix
			break
		}
	}
	if result.version == "" {
		saltCall := filepath.Join(executableDir, "salt-call")
		out, err := ExecCmdWithTimeout(timeouts.saltCall, saltCall, "--version")
		if match := diagnosticsSaltCallVersion.FindStringSubmatch(out); err == nil && match != nil {
			result.version = match[1]
		} else if err != nil {
			result.err = fmt.Sprintf("no salt package under %s, %s", strings.Join(prefixes, ", "), err.Error())
		} else {
			result.err = fmt.Sprintf("no salt package under %s, unexpected salt-call output: %s", strings.Join(prefixes, ", "), capLine(out))
		}
	}
	// the interpreter name can be more precise than a python3 directory
	if pythonVersion := pythonVersionOf(filepath.Base(interpreter)); interpreter != "" && len(pythonVersion) > len(result.pythonVersion) {
		result.pythonVersion = pythonVersion
	}
	return &result
}

// parseExecStartExecutable finds the salt executable in the ExecStart property of systemctl show, which looks
// like "{ path=/opt/salt/bin/salt-minion ; argv[]=/opt/salt/bin/salt-minion -d ; ignore_errors=no ; ... }". The
// executable can be the path itself or, when the unit starts it through an interpreter, one of the arguments.
func parseExecStartExecutable(execStart, name string) string {
	var candidates []string
	for _, part := range strings.Split(strings.Trim(execStart, "{} "), ";") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && (key == "path" || key == "argv[]") {
			candidates = append(candidates, strings.Fields(value)...)
		}
	}
	for _, candidate := range candidates {
		if filepath.Base(candidate) == name {
			return candidate
		}
	}
	return ""
}

// readShebangInterpreter returns the python interpreter of a script's #! line, looking through /usr/bin/env.
func readShebangInterpreter(file string) string {
	f, err := os.Open(file)
	if err != nil {
		return ""
	}
	defer closeIt(f)
	line, _ := bufio.NewReaderSize(f, 256).ReadString('\n')
	if !strings.HasPrefix(line, "#!") {
		return ""
	}
	fields := strings.Fields(line[2:])
	interpreter := ""
	if len(fields) > 1 && filepath.Base(fields[0]) == "env" {
		interpreter = fields[1]
	} else if len(fields) > 0 {
		interpreter = fields[0]
	}
	// onedir scripts start with #!/bin/sh, which says nothing about where salt is installed
	if !strings.HasPrefix(filepath.Base(interpreter), "python") {
		return ""
	}
	return interpreter
}

// installPrefix returns the directory an executable directory belongs to: /opt/salt_3006.10 for both
// /opt/salt_3006.10 and /opt/salt_3006.10/bin.
func installPrefix(executableDir string) string {
	if base := filepath.Base(executableDir); base == "bin" || base == "sbin" {
		return filepath.Dir(executableDir)
	}
	return executableDir
}

// findInstalledSaltVersion looks for the salt package in the python library directories of an install prefix and
// returns its version and the python version of the directory it was found in.
func findInstalledSaltVersion(prefix string) (version, pythonVersion string) {
	for _, lib := range []string{"/lib", "/lib64"} {
		entries, err := os.ReadDir(prefix + lib)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !strings.HasPrefix(entry.Name(), "python3") {
				continue
			}
			for _, packages := range []string{"site-packages", "dist-packages"} {
				dir := prefix + lib + "/" + entry.Name() + "/" + packages
				if version = readSaltPackageVersion(dir); version != "" {
					return version, pythonVersionOf(entry.Name())
				}
			}
		}
	}
	return "", ""
}

// readSaltPackageVersion reads the version from the salt package in a site-packages directory: salt/_version.txt,
// then the dist-info or egg-info metadata.
func readSaltPackageVersion(sitePackages string) string {
	if b, err := os.ReadFile(sitePackages + "/salt/_version.txt"); err == nil {
		if fields := strings.Fields(string(b)); len(fields) > 0 {
			return fields[0]
		}
	}
	entries, err := os.ReadDir(sitePackages)
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		if !diagnosticsSaltVersionDir.MatchString(entry.Name()) {
			continue
		}
		metadata := sitePackages + "/" + entry.Name()
		if strings.HasSuffix(entry.Name(), ".dist-info") {
			metadata += "/METADATA"
		} else if info, err := os.Stat(metadata); err == nil && info.IsDir() {
			metadata += "/PKG-INFO"
		}
		if b, err := os.ReadFile(metadata); err == nil {
			// the metadata is a mail style header, followed by the description after an empty line
			header, _, _ := strings.Cut(string(b), "\n\n")
			if version := parseKeyValueLines(header, ":")["Version"]; version != "" {
				return version
			}
		}
	}
	return ""
}

// pythonVersionOf returns 3.10 for python3.10 and 3 for python3, or "" for a name with no python in it.
func pythonVersionOf(name string) string {
	if match := diagnosticsPythonPattern.FindStringSubmatch(name); match != nil {
		return match[1]
	}
	return ""
}

func probeTime(timeouts probeTimeouts) TimeDiagnostics {
	result := TimeDiagnostics{Now: time.Now().UTC().Format(time.RFC3339)}
	out, err := ExecCmdWithTimeout(timeouts.command, "timedatectl", "show", "-p", "NTP", "-p", "NTPSynchronized")
	if err == nil {
		props := parseKeyValueLines(out, "=")
		result.NtpEnabled = parseOptionalBool(props["NTP"])
		result.NtpSynchronized = parseOptionalBool(props["NTPSynchronized"])
		return result
	}
	// systemd older than 239 has no "timedatectl show", only the human readable status
	out, statusErr := ExecCmdWithTimeout(timeouts.command, "timedatectl", "status")
	if statusErr != nil {
		result.Error = strings.TrimSpace(out + " " + statusErr.Error())
		return result
	}
	props := parseKeyValueLines(out, ":")
	result.NtpEnabled = parseOptionalBool(firstNonEmpty(props["NTP enabled"], props["NTP service"]))
	result.NtpSynchronized = parseOptionalBool(firstNonEmpty(props["NTP synchronized"], props["System clock synchronized"]))
	return result
}

// probeJobs lists the proc files of the salt-minion and, where the directory exists, of the salt-master, and reads
// worker_threads of the salt-master configuration. A missing directory is no error: it means no job has run yet.
func probeJobs(baseDir string) SaltJobsDiagnostics {
	var jobs SaltJobsDiagnostics
	var errs []string
	var err error
	now := diagnosticsNow()
	if jobs.MinionJobs, jobs.MinionJobsOmitted, err = readSaltJobs(baseDir+"/var/cache/salt/minion/proc", now); err != nil {
		errs = append(errs, "minion proc: "+err.Error())
	}
	if jobs.MasterJobs, jobs.MasterJobsOmitted, err = readSaltJobs(baseDir+"/var/cache/salt/master/proc", now); err != nil {
		errs = append(errs, "master proc: "+err.Error())
	}
	var workerErrs []string
	jobs.WorkerThreads, workerErrs = readWorkerThreads(baseDir)
	errs = append(errs, workerErrs...)
	jobs.Error = strings.Join(errs, "; ")
	return jobs
}

// readSaltJobs returns the oldest MaxJobs (configured) jobs of a proc directory, oldest first, and the number of the
// ones left out. The job ids sort by their start time.
func readSaltJobs(dir string, now time.Time) (jobs []SaltJobDiagnostics, omitted int, err error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		if len(jobs) == diagConfig().MaxJobs {
			omitted++
			continue
		}
		jobs = append(jobs, saltJob(entry.Name(), now))
	}
	return jobs, omitted, nil
}

// saltJob parses the job id, which is the start time of the job in the local time of the node, e.g.
// 20261118101500123456. A name that is no job id has no start time and age.
func saltJob(name string, now time.Time) SaltJobDiagnostics {
	job := SaltJobDiagnostics{Jid: name}
	if !diagnosticsJidPattern.MatchString(name) {
		return job
	}
	started, err := time.ParseInLocation("20060102150405.000000", name[:14]+"."+name[14:], time.Local)
	if err != nil {
		return job
	}
	age := max(int64(now.Sub(started).Seconds()), 0)
	job.StartedAt, job.AgeSeconds = started.Format(time.RFC3339), &age
	return job
}

// readWorkerThreads reads worker_threads from /etc/salt/master, then from /etc/salt/master.d/*.conf in sorted order;
// the last value wins, like in salt. It is nil if there is no value, e.g. on a node without a salt-master.
func readWorkerThreads(baseDir string) (workerThreads *int, errs []string) {
	files := []string{baseDir + "/etc/salt/master"}
	entries, err := os.ReadDir(baseDir + "/etc/salt/master.d")
	if err != nil && !os.IsNotExist(err) {
		errs = append(errs, "master.d: "+err.Error())
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".conf") {
			files = append(files, baseDir+"/etc/salt/master.d/"+entry.Name())
		}
	}
	for _, file := range files {
		b, err := os.ReadFile(file)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			errs = append(errs, filepath.Base(file)+": "+err.Error())
			continue
		}
		matches := diagnosticsWorkerThreads.FindAllSubmatch(b, -1)
		if len(matches) == 0 {
			continue
		}
		if value, err := strconv.Atoi(string(matches[len(matches)-1][1])); err == nil {
			workerThreads = &value
		}
	}
	return workerThreads, errs
}

func probeLoad(baseDir string) LoadDiagnostics {
	load := LoadDiagnostics{CpuCount: countCpus(baseDir)}
	b, err := os.ReadFile(baseDir + "/proc/loadavg")
	if err != nil {
		load.Error = "loadavg: " + err.Error()
		return load
	}
	fields := strings.Fields(string(b))
	if len(fields) < 3 {
		load.Error = "loadavg: unexpected format"
		return load
	}
	load.Load1 = parseOptionalFloat(fields[0])
	load.Load5 = parseOptionalFloat(fields[1])
	load.Load15 = parseOptionalFloat(fields[2])
	load.Load1PerCpu = perCpu(load.Load1, load.CpuCount)
	load.Load5PerCpu = perCpu(load.Load5, load.CpuCount)
	load.Load15PerCpu = perCpu(load.Load15, load.CpuCount)
	return load
}

func probeMemory(baseDir string) MemoryDiagnostics {
	var memory MemoryDiagnostics
	b, err := os.ReadFile(baseDir + "/proc/meminfo")
	if err != nil {
		memory.Error = "meminfo: " + err.Error()
		return memory
	}
	meminfo := parseKeyValueLines(string(b), ":")
	memory.TotalKb = parseOptionalKb(meminfo["MemTotal"])
	memory.AvailableKb = parseOptionalKb(meminfo["MemAvailable"])

	vmstat, err := os.ReadFile(baseDir + "/proc/vmstat")
	if err != nil {
		memory.Error = "vmstat: " + err.Error()
		return memory
	}
	// oom_kill is missing on kernels older than 4.13, so it stays nil there instead of reading as 0
	memory.OomKills = parseOptionalUint(parseKeyValueLines(string(vmstat), " ")["oom_kill"])
	return memory
}

// probeBootTime returns the boot time from btime in /proc/stat, which is in seconds since the epoch.
func probeBootTime(baseDir string) (string, error) {
	b, err := os.ReadFile(baseDir + "/proc/stat")
	if err != nil {
		return "", err
	}
	btime := parseOptionalUint(parseKeyValueLines(string(b), " ")["btime"])
	if btime == nil {
		return "", errors.New("btime is missing")
	}
	return time.Unix(int64(*btime), 0).UTC().Format(time.RFC3339), nil
}

// probeMounts reports the usage of the well-known directories that are a mount point of their own. The ones that
// are only a directory on / are left out, as the root filesystem covers them.
func probeMounts(baseDir string) ([]MountDiagnostics, error) {
	b, err := os.ReadFile(baseDir + "/proc/self/mounts")
	if err != nil {
		return nil, err
	}
	mountPoints := make(map[string]bool)
	for _, line := range strings.Split(string(b), "\n") {
		if fields := strings.Fields(line); len(fields) >= 2 {
			mountPoints[unescapeMountField(fields[1])] = true
		}
	}
	var mounts []MountDiagnostics
	for _, path := range diagConfig().MountPoints {
		if mountPoints[path] {
			mounts = append(mounts, MountDiagnostics{Path: path, FilesystemDiagnostics: probeFilesystem(baseDir, path)})
		}
	}
	return mounts, nil
}

func probeRootFilesystem(baseDir string) FilesystemDiagnostics {
	return probeFilesystem(baseDir, "/")
}

// probeFilesystem reports the size and the inodes of the filesystem holding path.
func probeFilesystem(baseDir, path string) FilesystemDiagnostics {
	var fs syscall.Statfs_t
	if err := syscall.Statfs(baseDir+path, &fs); err != nil {
		return FilesystemDiagnostics{Error: "statfs " + path + ": " + err.Error()}
	}
	total, available := fs.Blocks*uint64(fs.Bsize), fs.Bavail*uint64(fs.Bsize)
	filesystem := FilesystemDiagnostics{TotalBytes: &total, AvailableBytes: &available}
	// a filesystem with a dynamic inode table reports no inodes at all
	if fs.Files > 0 {
		totalInodes, freeInodes := fs.Files, fs.Ffree
		filesystem.TotalInodes, filesystem.FreeInodes = &totalInodes, &freeInodes
	}
	return filesystem
}

// countCpus counts the online CPUs in /proc/cpuinfo, the CPUs the kernel's load average is spread over. It falls
// back to the CPUs this process may run on when /proc/cpuinfo cannot be read.
func countCpus(baseDir string) int {
	b, err := os.ReadFile(baseDir + "/proc/cpuinfo")
	if err != nil {
		return runtime.NumCPU()
	}
	count := 0
	for _, line := range strings.Split(string(b), "\n") {
		if key, _, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(key) == "processor" {
			count++
		}
	}
	if count == 0 {
		return runtime.NumCPU()
	}
	return count
}

// perCpu divides load by cpus, rounded to two decimals.
func perCpu(load *float64, cpus int) *float64 {
	if load == nil || cpus <= 0 {
		return nil
	}
	normalized := math.Round(*load/float64(cpus)*100) / 100
	return &normalized
}

// probeLvm reports the LVM volume groups and logical volumes from vgs and lvs, plus the filesystem usage of
// every mounted LV. Both commands run read-only, so they take no LVM locks, and are killed after
// the configured LvmTimeout. Nodes without the LVM tools get no lvm section at all.
func probeLvm(baseDir string, timeouts probeTimeouts) *LvmDiagnostics {
	lvsPath, vgsPath := findTool("lvs"), findTool("vgs")
	if lvsPath == "" || vgsPath == "" {
		return nil
	}

	var lvm LvmDiagnostics
	var errs []string
	var vgsErr error
	var group probeGroup
	group.Go(func() { lvm.VolumeGroups, vgsErr = probeVolumeGroups(vgsPath, timeouts) })
	logicalVolumes, lvsErr := probeLogicalVolumes(lvsPath, timeouts)
	group.Wait()
	if vgsErr != nil {
		errs = append(errs, "vgs: "+vgsErr.Error())
	}
	if lvsErr != nil {
		errs = append(errs, "lvs: "+lvsErr.Error())
	}

	if len(logicalVolumes) > 0 {
		if err := addMountedFilesystems(baseDir, logicalVolumes); err != nil {
			errs = append(errs, "mounts: "+err.Error())
		}
	}
	lvm.LogicalVolumes = logicalVolumes
	lvm.Error = strings.Join(errs, "; ")
	return &lvm
}

// findTool looks the tool up on PATH and, as the service may run with a minimal PATH, in the sbin
// directories tools like LVM and faillock install to. It returns "" when the tool is not installed.
func findTool(name string) string {
	if path, err := lookPath(name); err == nil {
		return path
	}
	for _, dir := range []string{"/usr/sbin/", "/sbin/"} {
		if path, err := lookPath(dir + name); err == nil {
			return path
		}
	}
	return ""
}

type lvmReport struct {
	Report []struct {
		Vg []map[string]string `json:"vg"`
		Lv []map[string]string `json:"lv"`
	} `json:"report"`
}

func runLvmReport(executable string, fields string, timeout time.Duration) (lvmReport, error) {
	var report lvmReport
	out, err := ExecCmdWithTimeout(timeout, executable,
		"--readonly", "--reportformat", "json", "--units", "b", "--nosuffix", "-o", fields)
	if err != nil {
		return report, err
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		return report, fmt.Errorf("unexpected output: %s", capLine(out))
	}
	return report, nil
}

func probeVolumeGroups(vgsPath string, timeouts probeTimeouts) ([]VolumeGroupDiagnostics, error) {
	report, err := runLvmReport(vgsPath, "vg_name,vg_size,vg_free,lv_count,pv_count", timeouts.lvm)
	if err != nil {
		return nil, err
	}
	var volumeGroups []VolumeGroupDiagnostics
	for _, r := range report.Report {
		for _, vg := range r.Vg {
			volumeGroups = append(volumeGroups, VolumeGroupDiagnostics{
				Name:      vg["vg_name"],
				SizeBytes: parseOptionalUint(vg["vg_size"]),
				FreeBytes: parseOptionalUint(vg["vg_free"]),
				LvCount:   parseOptionalInt(vg["lv_count"]),
				PvCount:   parseOptionalInt(vg["pv_count"]),
			})
		}
	}
	return volumeGroups, nil
}

func probeLogicalVolumes(lvsPath string, timeouts probeTimeouts) ([]LogicalVolumeDiagnostics, error) {
	report, err := runLvmReport(lvsPath, "vg_name,lv_name,lv_path,lv_size,lv_attr,lv_active,pool_lv,data_percent,metadata_percent", timeouts.lvm)
	if err != nil {
		return nil, err
	}
	var logicalVolumes []LogicalVolumeDiagnostics
	for _, r := range report.Report {
		for _, lv := range r.Lv {
			logicalVolumes = append(logicalVolumes, LogicalVolumeDiagnostics{
				VolumeGroup:     lv["vg_name"],
				Name:            lv["lv_name"],
				Path:            lv["lv_path"],
				SizeBytes:       parseOptionalUint(lv["lv_size"]),
				Attributes:      lv["lv_attr"],
				Active:          lv["lv_active"] == "active",
				Pool:            lv["pool_lv"],
				DataPercent:     parseOptionalFloat(lv["data_percent"]),
				MetadataPercent: parseOptionalFloat(lv["metadata_percent"]),
			})
		}
	}
	return logicalVolumes, nil
}

// addMountedFilesystems matches the logical volumes to /proc/self/mounts and adds the mount points and the
// usage of their filesystem. A mount source can name an LV as /dev/mapper/<vg>-<lv>, /dev/<vg>/<lv> or /dev/dm-N.
func addMountedFilesystems(baseDir string, logicalVolumes []LogicalVolumeDiagnostics) error {
	bySource := make(map[string]*LogicalVolumeDiagnostics)
	for i := range logicalVolumes {
		lv := &logicalVolumes[i]
		mapperPath := "/dev/mapper/" + deviceMapperName(lv.VolumeGroup, lv.Name)
		bySource[mapperPath] = lv
		bySource["/dev/"+lv.VolumeGroup+"/"+lv.Name] = lv
		if target, err := os.Readlink(baseDir + mapperPath); err == nil {
			bySource["/dev/"+filepath.Base(target)] = lv
		}
	}

	mounts, err := os.ReadFile(baseDir + "/proc/self/mounts")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(mounts), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		lv := bySource[unescapeMountField(fields[0])]
		if lv == nil {
			continue
		}
		mountPoint := unescapeMountField(fields[1])
		if len(lv.MountPoints) == 0 {
			lv.FsType = fields[2]
			fs := probeFilesystem(baseDir, mountPoint)
			lv.FsTotalBytes, lv.FsAvailableBytes = fs.TotalBytes, fs.AvailableBytes
			lv.FsTotalInodes, lv.FsFreeInodes = fs.TotalInodes, fs.FreeInodes
			lv.Error = fs.Error
		}
		lv.MountPoints = append(lv.MountPoints, mountPoint)
	}
	return nil
}

// deviceMapperName returns the device-mapper name LVM gives a logical volume: volume group and logical volume
// joined with '-', with every '-' inside the names doubled, so my-vg/var-log becomes "my--vg-var--log".
func deviceMapperName(vg, lv string) string {
	return strings.ReplaceAll(vg, "-", "--") + "-" + strings.ReplaceAll(lv, "-", "--")
}

// unescapeMountField undoes the octal escaping /proc/self/mounts uses for space, tab, newline and backslash.
func unescapeMountField(field string) string {
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(field)
}

func probeLogs(baseDir string, lines int) []LogDiagnostics {
	logs := make([]LogDiagnostics, 0, len(diagConfig().LogFiles))
	for _, path := range slices.Sorted(maps.Keys(diagConfig().LogFiles)) {
		if _, err := os.Stat(baseDir + path); !diagConfig().LogFiles[path] && os.IsNotExist(err) {
			continue
		}
		logs = append(logs, tailLog(baseDir+path, path, lines))
	}
	return logs
}

// tailLog returns the last n redacted lines of the file, reading no more than its final LogWindowBytes (configured).
func tailLog(file, path string, n int) LogDiagnostics {
	result := LogDiagnostics{Path: path, Lines: []string{}}
	f, err := os.Open(file)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer closeIt(f)

	info, err := f.Stat()
	if err != nil {
		result.Error = err.Error()
		return result
	}
	offset := max(0, info.Size()-int64(diagConfig().LogWindowBytes))
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		result.Error = err.Error()
		return result
	}

	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), diagConfig().LogWindowBytes+1)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		result.Error = err.Error()
	}
	if offset > 0 && len(lines) > 0 {
		// the window most likely starts mid-line
		lines = lines[1:]
		result.Truncated = true
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
		result.Truncated = true
	}
	for _, line := range lines {
		result.Lines = append(result.Lines, capLine(redactLine(line)))
	}
	return result
}

func redactLine(line string) string {
	line = diagnosticsAuthPattern.ReplaceAllString(line, "$1 ***")
	line = diagnosticsURLUserinfoPattern.ReplaceAllString(line, "${1}***@")
	line = diagnosticsFlagPattern.ReplaceAllString(line, "${1}${2}${3}***${2}${3}")
	line = diagnosticsSecretPattern.ReplaceAllString(line, "${1}${2}${3}***${2}${3}")
	return diagnosticsPassPattern.ReplaceAllString(line, "${1}${2}${3}***${2}${3}")
}

func capLine(line string) string {
	if len(line) <= diagConfig().MaxLineBytes {
		return line
	}
	return line[:diagConfig().MaxLineBytes] + "...[truncated]"
}

func parseKeyValueLines(out, separator string) map[string]string {
	props := make(map[string]string)
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(line, separator)
		if ok {
			props[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	return props
}

func parseOptionalInt(value string) *int {
	i, err := strconv.Atoi(value)
	if err != nil {
		return nil
	}
	return &i
}

func parseOptionalUint(value string) *uint64 {
	u, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
	if err != nil {
		return nil
	}
	return &u
}

func parseOptionalFloat(value string) *float64 {
	f, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return nil
	}
	return &f
}

// parseOptionalKb parses a /proc/meminfo value such as "16314284 kB".
func parseOptionalKb(value string) *uint64 {
	kb, err := strconv.ParseUint(strings.TrimSpace(strings.TrimSuffix(value, "kB")), 10, 64)
	if err != nil {
		return nil
	}
	return &kb
}

func parseOptionalBool(value string) *bool {
	var b bool
	switch strings.ToLower(value) {
	case "yes", "active", "true":
		b = true
	case "no", "inactive", "false":
		b = false
	default:
		return nil
	}
	return &b
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// checkFinding is one problem a check found. message already names the node it is about; nodes are all the
// addresses involved, e.g. the minion and the master of a missing key.
type checkFinding struct {
	fail    bool
	message string
	nodes   []string
}

type checkFindings []checkFinding

func (f *checkFindings) add(fail bool, address, text string, involved []string) {
	if address != "" {
		text = address + ": " + text
		involved = append([]string{address}, involved...)
	}
	*f = append(*f, checkFinding{fail: fail, message: text, nodes: involved})
}

// fail and warn report a problem of the node at address; involved are the other nodes it concerns.
func (f *checkFindings) fail(address, text string, involved ...string) {
	f.add(true, address, text, involved)
}
func (f *checkFindings) warn(address, text string, involved ...string) {
	f.add(false, address, text, involved)
}

// result turns the findings into the check: fail if any finding is a failure, warn if there are only warnings and
// ok with okMessage if there are none. The failures are listed first.
func (f checkFindings) result(id, okMessage string) DiagnosticsCheck {
	if len(f) == 0 {
		return DiagnosticsCheck{Id: id, Status: diagnosticsCheckOk, Message: okMessage}
	}
	check := DiagnosticsCheck{Id: id, Status: diagnosticsCheckWarn}
	var messages []string
	seen := map[string]bool{}
	for _, failures := range []bool{true, false} {
		for _, finding := range f {
			if finding.fail != failures {
				continue
			}
			if failures {
				check.Status = diagnosticsCheckFail
			}
			messages = append(messages, finding.message)
			for _, node := range finding.nodes {
				if !seen[node] {
					seen[node] = true
					check.Nodes = append(check.Nodes, node)
				}
			}
		}
	}
	check.Message = strings.Join(messages, "; ")
	return check
}

func skippedDiagnosticsCheck(id, reason string) DiagnosticsCheck {
	return DiagnosticsCheck{Id: id, Status: diagnosticsCheckSkipped, Message: reason}
}

// computeDiagnosticsChecks evaluates the cross-node checks over the nodes of a distribute response. It returns one
// entry per check in a fixed order. requestedUnits are the units the request asked for. The nodes are evaluated
// in the order of their addresses, so the same nodes always give the same messages.
func computeDiagnosticsChecks(nodes []NodeDiagnostics, requestedUnits []string) []DiagnosticsCheck {
	return runDiagnosticsChecks(diagnosticsCheckEntries(nodes, requestedUnits))
}

func diagnosticsCheckEntries(nodes []NodeDiagnostics, requestedUnits []string) []diagnosticsCheckEntry {
	// the nodes report the units by their canonical names
	requestedUnits = slices.Clone(requestedUnits)
	for i, name := range requestedUnits {
		requestedUnits[i] = canonicalUnitName(name)
	}
	nodes = slices.SortedStableFunc(slices.Values(withoutPorts(nodes)), func(a, b NodeDiagnostics) int { return strings.Compare(a.Address, b.Address) })
	var answered []NodeDiagnostics
	for _, node := range nodes {
		if node.StatusCode == http.StatusOK {
			answered = append(answered, node)
		}
	}
	masters := saltMasters(answered)
	return []diagnosticsCheckEntry{
		{"node-reachable", func() DiagnosticsCheck { return checkNodeReachable(nodes) }},
		{"timed-out-probes", func() DiagnosticsCheck { return checkTimedOutProbes(answered) }},
		{"config-consistent", func() DiagnosticsCheck { return checkConfigConsistent(answered, diagConfig()) }},
		{"salt-units", func() DiagnosticsCheck { return checkSaltUnits(answered, masters, requestedUnits) }},
		{"additional-units", func() DiagnosticsCheck { return checkAdditionalUnits(answered, requestedUnits) }},
		{"master-ports", func() DiagnosticsCheck { return checkMasterPorts(answered) }},
		{"master-keys-consistent", func() DiagnosticsCheck { return checkMasterKeysConsistent(masters) }},
		{"minion-master-key", func() DiagnosticsCheck { return checkMinionMasterKey(answered, masters) }},
		{"minion-key-accepted", func() DiagnosticsCheck { return checkMinionKeyAccepted(answered, masters) }},
		{"unknown-accepted-keys", func() DiagnosticsCheck { return checkUnknownAcceptedKeys(answered, masters) }},
		{"minion-id", func() DiagnosticsCheck { return checkMinionId(answered) }},
		{"host-resolution", func() DiagnosticsCheck { return checkHostResolution(answered) }},
		{"salt-version", func() DiagnosticsCheck { return checkSaltVersion(answered, masters) }},
		{"salt-user", func() DiagnosticsCheck { return checkSaltUser(masters) }},
		{"salt-jobs", func() DiagnosticsCheck { return checkSaltJobs(answered, masters) }},
		{"clock", func() DiagnosticsCheck { return checkClock(answered) }},
		{"resources", func() DiagnosticsCheck { return checkResources(answered) }},
	}
}

// withoutPorts drops the salt-bootstrap port from the node addresses, so the checks name the nodes by host. A host
// that two targets share keeps the ports, as the checks tell the nodes apart by their address. Only the copies the
// checks work on change; the nodes of the response keep the address they were reached at.
func withoutPorts(nodes []NodeDiagnostics) []NodeDiagnostics {
	targets := map[string]int{}
	for _, node := range nodes {
		targets[hostOf(node.Address)]++
	}
	result := slices.Clone(nodes)
	for i := range result {
		if host := hostOf(result[i].Address); targets[host] == 1 {
			result[i].Address = host
		}
	}
	return result
}

// hostOf returns the host of a host:port address, or the address itself when it has no port.
func hostOf(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}
	return host
}

// diagnosticsCheckEntry is a check with the id it reports, which has to be the id the check function itself uses.
type diagnosticsCheckEntry struct {
	id  string
	run func() DiagnosticsCheck
}

// runDiagnosticsChecks runs the checks in order. A check that panics, e.g. on unexpected node data, becomes an
// error check with its id, so it neither hides the other checks nor fails the whole request.
func runDiagnosticsChecks(entries []diagnosticsCheckEntry) []DiagnosticsCheck {
	checks := make([]DiagnosticsCheck, 0, len(entries))
	for _, entry := range entries {
		checks = append(checks, runDiagnosticsCheck(entry))
	}
	return checks
}

func runDiagnosticsCheck(entry diagnosticsCheckEntry) (check DiagnosticsCheck) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[computeDiagnosticsChecks] [ERROR] check %s panicked: %v\n%s", entry.id, r, debug.Stack())
			check = DiagnosticsCheck{Id: entry.id, Status: diagnosticsCheckError, Message: fmt.Sprintf("check failed: %v", r)}
		}
	}()
	return entry.run()
}

// computeChecks is replaced in tests.
var computeChecks = computeDiagnosticsChecks

// safeDiagnosticsChecks returns no checks if the computation as a whole panics, so the nodes can still be returned.
func safeDiagnosticsChecks(nodes []NodeDiagnostics, requestedUnits []string) (checks []DiagnosticsCheck) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[computeDiagnosticsChecks] [ERROR] computing the checks panicked: %v\n%s", r, debug.Stack())
			checks = nil
		}
	}()
	return computeChecks(nodes, requestedUnits)
}

// saltMasters picks the nodes that run a salt-master out of the answered nodes. A salt-master pki directory is no
// proof: images that install salt-master everywhere have one on every node, while only some run salt-master. A node is a
// master if it has a master section and it is one of the masters the minions are configured with (the union of
// the master.conf entries of the answered nodes): the host of its address, one of its interface addresses, its
// FQDN or its hostname matches such an entry, an IP in whatever notation. If no node reports a configured master,
// a node with a master section is a master if its salt-master unit is active or it has a saltuser account.
func saltMasters(nodes []NodeDiagnostics) []NodeDiagnostics {
	configured := map[string]bool{}
	for _, node := range nodes {
		if node.Minion != nil {
			for _, master := range node.Minion.Masters {
				if master.Id != "" {
					configured[addressKey(master.Id)] = true
				}
			}
		}
	}
	var masters []NodeDiagnostics
	for _, node := range nodes {
		if node.Master == nil {
			continue
		}
		if len(configured) > 0 {
			if slices.ContainsFunc(nodeIdentities(node), func(identity string) bool { return configured[addressKey(identity)] }) {
				masters = append(masters, node)
			}
			continue
		}
		active := slices.ContainsFunc(node.Units, func(unit UnitDiagnostics) bool {
			return unit.Name == "salt-master" && unit.ActiveState == "active"
		})
		if active || node.SaltUser != nil && node.SaltUser.Present {
			masters = append(masters, node)
		}
	}
	return masters
}

// addressKey is the key two names share if they are the same IP in whatever notation, or the same name in lower case.
func addressKey(name string) string {
	if ip := net.ParseIP(name); ip != nil {
		return ip.String()
	}
	return strings.ToLower(name)
}

// nodeIdentities are the names a master.conf entry can refer to a node by, in lower case.
func nodeIdentities(node NodeDiagnostics) []string {
	address, _, err := net.SplitHostPort(node.Address)
	if err != nil {
		address = node.Address
	}
	identities := []string{address}
	if node.Host != nil {
		identities = append(identities, node.Host.Addresses...)
		identities = append(identities, node.Host.Fqdn, node.Host.Hostname)
	}
	identities = slices.DeleteFunc(identities, func(identity string) bool { return identity == "" })
	for i := range identities {
		identities[i] = strings.ToLower(identities[i])
	}
	return identities
}

// shortText keeps the first line of text and cuts it to the configured CheckTextLength characters.
func shortText(text string) string {
	text, _, _ = strings.Cut(strings.TrimSpace(text), "\n")
	if len(text) > diagConfig().CheckTextLength {
		return text[:diagConfig().CheckTextLength] + "..."
	}
	return text
}

// shortFingerprint cuts a key fingerprint to a prefix that still tells keys apart in a message.
func shortFingerprint(fingerprint string) string {
	if len(fingerprint) > 12 {
		return fingerprint[:12] + "..."
	}
	return fingerprint
}

// limitedList joins at most the configured CheckListLength items and counts the rest.
func limitedList(items []string) string {
	if len(items) <= diagConfig().CheckListLength {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(items[:diagConfig().CheckListLength], ", "), len(items)-diagConfig().CheckListLength)
}

// id is the id the salt-minion runs with: the configured one, else the one it cached.
func (m *MinionDiagnostics) id() string {
	return firstNonEmpty(m.IdConfig, m.CachedId)
}

func checkNodeReachable(nodes []NodeDiagnostics) DiagnosticsCheck {
	const id = "node-reachable"
	if len(nodes) == 0 {
		return skippedDiagnosticsCheck(id, "no nodes")
	}
	var findings checkFindings
	for _, node := range nodes {
		switch {
		case node.StatusCode == http.StatusOK:
		case node.StatusCode == http.StatusNotFound:
			findings.warn(node.Address, "404, older salt-bootstrap without the diagnostics route")
		default:
			findings.fail(node.Address, fmt.Sprintf("status %d: %s", node.StatusCode, shortText(node.ErrorText)))
		}
	}
	return findings.result(id, fmt.Sprintf("%d nodes answered", len(nodes)))
}

func checkTimedOutProbes(nodes []NodeDiagnostics) DiagnosticsCheck {
	const id = "timed-out-probes"
	if len(nodes) == 0 {
		return skippedDiagnosticsCheck(id, "no node answered")
	}
	var findings checkFindings
	for _, node := range nodes {
		if len(node.TimedOutProbes) > 0 {
			findings.warn(node.Address, "probes timed out: "+strings.Join(node.TimedOutProbes, ", "))
		}
		if len(node.FailedProbes) > 0 {
			findings.warn(node.Address, "probes failed: "+strings.Join(node.FailedProbes, ", "))
		}
	}
	return findings.result(id, "no probe timed out or failed")
}

// checkSaltUnits fails for a salt-minion, or a salt-master and salt-api that exist on a salt-master node, which is
// not active; a salt-master node without a salt-master unit fails too. On other nodes these two units are
// not expected to run, so they only count if requested, and then only as a warning, as the caller may ask about a
// unit it expects to fail. salt-bootstrap that is not active is only a warning too: the node answered, so it runs, just
// not as the systemd unit, and a restart would not bring it back. Requested units that are no salt units are left to
// checkAdditionalUnits.
func checkSaltUnits(nodes, masters []NodeDiagnostics, requestedUnits []string) DiagnosticsCheck {
	const id = "salt-units"
	var findings checkFindings
	reported := false
	for _, node := range nodes {
		isMaster := slices.ContainsFunc(masters, func(master NodeDiagnostics) bool { return master.Address == node.Address })
		if isMaster && missingSaltMaster(node) {
			findings.fail(node.Address, "salt-master not found")
		}
		for _, unit := range node.Units {
			reported = true
			// a process stuck in I/O wait cannot be stopped, so stopping the minion times out
			if isSaltUnit(unit.Name) && unit.Process != nil && strings.HasPrefix(unit.Process.State, "D") {
				findings.warn(node.Address, unit.Name+" main process is in uninterruptible I/O wait (D state)")
			}
			fail, relevant := false, false
			switch {
			case unit.Name == "salt-minion":
				fail, relevant = true, true
			case unit.Name == "salt-bootstrap":
				relevant = true
			case unit.Name == "salt-master" && isMaster && unit.LoadState == "not-found":
				// reported above
				continue
			case (unit.Name == "salt-master" || unit.Name == "salt-api") && isMaster && unit.LoadState != "not-found":
				fail, relevant = true, true
			case isSaltUnit(unit.Name) && slices.Contains(requestedUnits, unit.Name):
				relevant = true
			}
			if relevant {
				findings.unitState(fail, node.Address, unit)
			}
		}
	}
	if !reported {
		return skippedDiagnosticsCheck(id, "no unit state reported")
	}
	return findings.result(id, "salt units are active")
}

// checkAdditionalUnits warns about the requested units that are no salt units and are not active. It never fails,
// as the caller may ask about a unit it expects to be down; the salt units are judged by checkSaltUnits.
func checkAdditionalUnits(nodes []NodeDiagnostics, requestedUnits []string) DiagnosticsCheck {
	const id = "additional-units"
	var additional []string
	for _, name := range requestedUnits {
		if !isSaltUnit(name) && !slices.Contains(additional, name) {
			additional = append(additional, name)
		}
	}
	if len(additional) == 0 {
		return skippedDiagnosticsCheck(id, "no additional units requested")
	}
	// the same problem on many nodes, e.g. an agent that is not installed anywhere, makes one finding
	var groups problemGroups
	reported := false
	for _, node := range nodes {
		for _, unit := range node.Units {
			// a rejected unit is always a requested one, even if its name was cut in the report
			if !slices.Contains(additional, unit.Name) && unit.Rejected == "" {
				continue
			}
			reported = true
			if problem, found := unitProblem(unit); found {
				// a unit that was not probed is a problem of the request, not one the caller may expect
				groups.add(unit.Rejected != "", problem, node.Address)
			}
		}
	}
	if !reported {
		return skippedDiagnosticsCheck(id, "no unit state reported")
	}
	return groups.findings().result(id, "additional units are active")
}

// problemGroups collects problems by their text, so the same problem on many nodes makes one finding.
type problemGroups struct {
	problems []string
	fail     map[string]bool
	affected map[string][]string
}

func (g *problemGroups) add(fail bool, problem, address string) {
	if g.affected == nil {
		g.fail, g.affected = map[string]bool{}, map[string][]string{}
	}
	if _, known := g.affected[problem]; !known {
		g.problems = append(g.problems, problem)
	}
	g.fail[problem] = g.fail[problem] || fail
	g.affected[problem] = append(g.affected[problem], address)
}

// findings names the node of a problem found on one node; for several the message only counts them, as the nodes
// field of the check lists them.
func (g *problemGroups) findings() checkFindings {
	return g.findingsWith("%s on %d nodes")
}

// findingsWith is findings with the format of a problem found on several nodes, given the problem and their count.
func (g *problemGroups) findingsWith(severalNodes string) checkFindings {
	var findings checkFindings
	for _, problem := range g.problems {
		if addresses := g.affected[problem]; len(addresses) == 1 {
			findings.add(g.fail[problem], addresses[0], problem, nil)
		} else {
			findings.add(g.fail[problem], "", fmt.Sprintf(severalNodes, problem, len(addresses)), addresses)
		}
	}
	return findings
}

// checkConfigConsistent compares the diagnostics configuration of the answered nodes with the one of the node
// running the fan-out. A node whose probe deadline leaves less than diagnosticsResponseMargin of the fan-out timeout
// fails, as it is reported unreachable whenever its probes take that long; a different or unusable configuration is a warning.
func checkConfigConsistent(nodes []NodeDiagnostics, config *DiagnosticsConfig) DiagnosticsCheck {
	const id = "config-consistent"
	fingerprint := config.fingerprint()
	var groups problemGroups
	reported := false
	for _, node := range nodes {
		if node.ConfigFingerprint == "" {
			// an older salt-bootstrap without the configuration file
			continue
		}
		reported = true
		if deadline, err := time.ParseDuration(node.ProbeDeadline); err == nil && !deadlineLeavesMargin(deadline, config.DistributeTimeout) {
			groups.add(true, fmt.Sprintf("probeDeadline %s leaves less than %s of the distributeTimeout %s of the fan-out node for the response",
				deadline, diagnosticsResponseMargin, config.DistributeTimeout), node.Address)
		}
		if node.ConfigError != "" {
			groups.add(false, "diagnostics configuration not usable, defaults in use: "+shortText(node.ConfigError), node.Address)
		} else if node.ConfigFingerprint != fingerprint {
			groups.add(false, "diagnostics configuration differs from the fan-out node", node.Address)
		}
	}
	if !reported {
		return skippedDiagnosticsCheck(id, "no node reports its diagnostics configuration")
	}
	return groups.findings().result(id, "nodes use the diagnostics configuration of the fan-out node")
}

// isSaltUnit tells whether the unit is one of the built-in salt units, with or without its ".service" suffix.
func isSaltUnit(name string) bool {
	_, salt := diagConfig().Units[canonicalUnitName(name)]
	return salt
}

// canonicalUnitName drops the ".service" suffix, as systemd treats "nginx" and "nginx.service" as the same unit and
// the report must not list it twice. Other types, e.g. ".socket", stay as given.
func canonicalUnitName(name string) string {
	return strings.TrimSuffix(name, ".service")
}

// unitState adds a finding for a unit that is not active, a failure if fail is set. A unit whose state could not
// be read is only a warning, as that is not the same as the unit being down.
func (f *checkFindings) unitState(fail bool, address string, unit UnitDiagnostics) {
	if problem, found := unitProblem(unit); found {
		f.add(fail && unit.Error == "", address, problem, nil)
	}
}

// unitProblem describes what is wrong with a unit that is not active or crash-looping; found is false otherwise.
func unitProblem(unit UnitDiagnostics) (problem string, found bool) {
	switch {
	case unit.Rejected != "":
		return fmt.Sprintf("%s rejected: %s", unit.Name, unit.Rejected), true
	case unit.Error != "":
		return fmt.Sprintf("%s state unknown: %s", unit.Name, shortText(unit.Error)), true
	case unit.LoadState == "not-found":
		return unit.Name + " not found", true
	case unit.ActiveState != "active":
		state := firstNonEmpty(unit.ActiveState, "unknown")
		if unit.SubState != "" {
			state += " (" + unit.SubState + ")"
		}
		return fmt.Sprintf("%s is %s", unit.Name, state), true
	case isCrashLooping(unit):
		return fmt.Sprintf("%s is crash-looping: restarted %d times, the current process is up %ds", unit.Name,
			*unit.NRestarts, *unit.Process.UptimeSeconds), true
	}
	return "", false
}

// isCrashLooping tells whether systemd keeps restarting a unit that is active only between its crashes: a simple
// service counts as running as soon as its process starts, so the state alone does not show a process that exits a
// second later. systemd keeps NRestarts until the unit is started by hand, so old restarts only count together with
// a process that is younger than crashLoopUptime.
func isCrashLooping(unit UnitDiagnostics) bool {
	config := diagConfig()
	return unit.NRestarts != nil && *unit.NRestarts >= config.CrashLoopRestarts &&
		unit.Process != nil && unit.Process.UptimeSeconds != nil && *unit.Process.UptimeSeconds < int64(config.CrashLoopUptime.Seconds())
}

// missingSaltMaster tells whether the units a node reported hold no salt-master that exists. A node whose units
// could not be read is not judged.
func missingSaltMaster(node NodeDiagnostics) bool {
	if len(node.Units) == 0 || slices.Contains(node.TimedOutProbes, "units") {
		return false
	}
	for _, unit := range node.Units {
		if unit.Error != "" || unit.Name == "salt-master" && unit.LoadState != "not-found" {
			return false
		}
	}
	return true
}

func checkMasterPorts(nodes []NodeDiagnostics) DiagnosticsCheck {
	const id = "master-ports"
	// a master that is down or firewalled is unreachable from every minion, which makes one finding
	var groups problemGroups
	probed := false
	for _, node := range nodes {
		if node.Minion == nil {
			continue
		}
		for _, master := range node.Minion.Masters {
			var unreachable []string
			for _, port := range master.Ports {
				probed = true
				if !port.Reachable {
					unreachable = append(unreachable, strconv.Itoa(port.Port))
				}
			}
			if len(unreachable) > 0 {
				ports := "port"
				if len(unreachable) > 1 {
					ports = "ports"
				}
				groups.add(true, fmt.Sprintf("master %s %s %s unreachable", master.Id, ports, strings.Join(unreachable, ",")), node.Address)
			}
		}
	}
	if !probed {
		return skippedDiagnosticsCheck(id, "no master port was checked")
	}
	return groups.findingsWith("%s from %d nodes").result(id, "master ports are reachable")
}

// masterKeysUnknown tells why the keys of a master are not known: its master probe timed out or failed, so its
// master section only holds what the saltVersion probe added, and empty key data is no proof of anything.
func masterKeysUnknown(node NodeDiagnostics) string {
	if slices.Contains(node.TimedOutProbes, "master") {
		return "timed out"
	}
	if slices.ContainsFunc(node.FailedProbes, func(failure string) bool { return strings.HasPrefix(failure, "master:") }) {
		return "failed"
	}
	return ""
}

// mastersWithKeys returns the masters whose key data is known, and warns once for every other master.
func mastersWithKeys(masters []NodeDiagnostics, findings *checkFindings) []NodeDiagnostics {
	var known []NodeDiagnostics
	for _, master := range masters {
		if reason := masterKeysUnknown(master); reason != "" {
			findings.warn(master.Address, "master probe "+reason+", keys not checked")
		} else {
			known = append(known, master)
		}
	}
	return known
}

// checkMasterKeysConsistent compares the keys of the salt-masters: multi-master salt requires them to share one.
func checkMasterKeysConsistent(masters []NodeDiagnostics) DiagnosticsCheck {
	const id = "master-keys-consistent"
	var findings checkFindings
	var withKey []NodeDiagnostics
	distinct := map[string]bool{}
	for _, master := range mastersWithKeys(masters, &findings) {
		if master.Master.KeyFingerprint != "" {
			withKey = append(withKey, master)
			distinct[master.Master.KeyFingerprint] = true
		}
	}
	if len(withKey) < 2 {
		if len(findings) > 0 {
			return findings.result(id, "")
		}
		return skippedDiagnosticsCheck(id, "fewer than two salt-masters with a key among the targets")
	}
	if len(distinct) > 1 {
		for _, master := range withKey {
			findings.fail(master.Address, "master key "+shortFingerprint(master.Master.KeyFingerprint)+" differs between masters")
		}
	}
	return findings.result(id, "all salt-masters share one key")
}

// checkMinionMasterKey compares the master key every minion holds with the keys of the masters among the targets.
func checkMinionMasterKey(nodes, masters []NodeDiagnostics) DiagnosticsCheck {
	const id = "minion-master-key"
	masterKeys, signKeys := map[string]bool{}, map[string]bool{}
	var findings checkFindings
	known := mastersWithKeys(masters, &findings)
	// the key of a master with unknown keys may be the one a minion holds, so a mismatch is only a warning then
	conclusive := len(known) == len(masters)
	for _, master := range known {
		if master.Master.KeyFingerprint != "" {
			masterKeys[master.Master.KeyFingerprint] = true
		}
		if master.Master.SignKeyFingerprint != "" {
			signKeys[master.Master.SignKeyFingerprint] = true
		}
	}
	if len(masterKeys) == 0 {
		if len(findings) > 0 {
			return findings.result(id, "")
		}
		return skippedDiagnosticsCheck(id, "no salt-master key among the targets")
	}
	minions := 0
	for _, node := range nodes {
		if node.Minion == nil {
			continue
		}
		minions++
		switch fingerprint := node.Minion.MasterKeyFingerprint; {
		case fingerprint == "":
			findings.warn(node.Address, "no master key fingerprint")
		case !masterKeys[fingerprint]:
			findings.add(conclusive, node.Address, "master key "+shortFingerprint(fingerprint)+" matches no target master", nil)
		}
		if fingerprint := node.Minion.MasterSignKeyFingerprint; fingerprint != "" && len(signKeys) > 0 && !signKeys[fingerprint] {
			findings.add(conclusive, node.Address, "master sign key "+shortFingerprint(fingerprint)+" matches no target master", nil)
		}
	}
	if minions == 0 {
		return skippedDiagnosticsCheck(id, "no minion data")
	}
	return findings.result(id, "minions hold the key of their master")
}

// checkMinionKeyAccepted looks for the key of every minion in the key directories of every master among the targets.
// The minions with the same problem on a master make one finding, so a cluster-wide problem stays readable.
func checkMinionKeyAccepted(nodes, masters []NodeDiagnostics) DiagnosticsCheck {
	const id = "minion-key-accepted"
	if len(masters) == 0 {
		return skippedDiagnosticsCheck(id, "no salt-master among the targets")
	}
	var findings checkFindings
	checked := 0
	for _, node := range nodes {
		if node.Minion != nil && node.Minion.Fingerprint != "" && node.Minion.id() != "" {
			checked++
		}
	}
	for _, master := range mastersWithKeys(masters, &findings) {
		// the last accepted key and the first other key of every minion id on this master
		acceptedKeys, otherKeys := map[string]*MasterMinionDiagnostics{}, map[string]*MasterMinionDiagnostics{}
		for i, key := range master.Master.Minions {
			if key.KeyState == "accepted" {
				acceptedKeys[key.Id] = &master.Master.Minions[i]
			} else if otherKeys[key.Id] == nil {
				otherKeys[key.Id] = &master.Master.Minions[i]
			}
		}
		// the problems in the order they were found, with the ids and addresses of the minions they affect
		var problems []string
		minionIds, minionNodes := map[string][]string{}, map[string][]string{}
		problem := func(text string, node NodeDiagnostics) {
			if _, known := minionIds[text]; !known {
				problems = append(problems, text)
			}
			minionIds[text] = append(minionIds[text], node.Minion.id())
			minionNodes[text] = append(minionNodes[text], node.Address)
		}
		for _, node := range nodes {
			if node.Minion == nil || node.Minion.Fingerprint == "" || node.Minion.id() == "" {
				continue
			}
			minionId := node.Minion.id()
			accepted, other := acceptedKeys[minionId], otherKeys[minionId]
			switch {
			case accepted != nil && accepted.Fingerprint == "":
				// the key file could not be read, so the master's key is not known to differ
			case accepted != nil && accepted.Fingerprint != node.Minion.Fingerprint:
				problem("different key cached", node)
			case accepted != nil:
			case other != nil:
				problem("keys "+other.KeyState, node)
			case master.Master.Error != "":
				// the key directories may not have been readable
				findings.warn(node.Address, fmt.Sprintf("key of minion %s unknown on master %s: %s", minionId, master.Address, shortText(master.Master.Error)), master.Address)
			default:
				problem("keys absent", node)
			}
		}
		for _, text := range problems {
			findings.fail("", fmt.Sprintf("master %s: %s for minions %s", master.Address, text, limitedList(minionIds[text])),
				append([]string{master.Address}, minionNodes[text]...)...)
		}
	}
	if checked == 0 {
		return skippedDiagnosticsCheck(id, "no minion with a key fingerprint and an id")
	}
	return findings.result(id, "minion keys are accepted on all masters")
}

// checkUnknownAcceptedKeys finds accepted keys that belong to none of the targets. It can only warn, as the
// request may have targeted a subset of the cluster.
func checkUnknownAcceptedKeys(nodes, masters []NodeDiagnostics) DiagnosticsCheck {
	const id = "unknown-accepted-keys"
	if len(masters) == 0 {
		return skippedDiagnosticsCheck(id, "no salt-master among the targets")
	}
	minionIds := map[string]bool{}
	for _, node := range nodes {
		if node.Minion != nil {
			minionIds[node.Minion.IdConfig], minionIds[node.Minion.CachedId] = true, true
		}
	}
	delete(minionIds, "")
	if len(minionIds) == 0 {
		return skippedDiagnosticsCheck(id, "no minion id reported")
	}
	var findings checkFindings
	subset := false
	for _, master := range mastersWithKeys(masters, &findings) {
		var unknown []string
		for _, key := range master.Master.Minions {
			if key.KeyState == "accepted" && !minionIds[key.Id] {
				unknown = append(unknown, key.Id)
			}
		}
		if len(unknown) > 0 {
			findings.warn(master.Address, "accepted keys of unknown minions: "+limitedList(unknown))
			subset = true
		}
	}
	check := findings.result(id, "all accepted keys belong to a target")
	if subset {
		check.Message += " (expected if only a subset of the cluster was targeted)"
	}
	return check
}

func checkMinionId(nodes []NodeDiagnostics) DiagnosticsCheck {
	const id = "minion-id"
	var findings checkFindings
	owners := map[string][]string{}
	var ids []string
	for _, node := range nodes {
		if node.Minion == nil || node.Minion.id() == "" {
			continue
		}
		minion := node.Minion
		if minion.IdConfig != "" && minion.CachedId != "" && minion.IdConfig != minion.CachedId {
			findings.fail(node.Address, fmt.Sprintf("minion id %s in minion_id.conf differs from the cached id %s", minion.IdConfig, minion.CachedId))
		}
		if _, known := owners[minion.id()]; !known {
			ids = append(ids, minion.id())
		}
		owners[minion.id()] = append(owners[minion.id()], node.Address)
		if node.Host != nil && node.Host.Fqdn != "" && node.Host.Fqdn != minion.id() {
			findings.warn(node.Address, fmt.Sprintf("minion id %s differs from the FQDN %s", minion.id(), node.Host.Fqdn))
		}
	}
	if len(ids) == 0 {
		return skippedDiagnosticsCheck(id, "no minion id reported")
	}
	for _, minionId := range ids {
		if len(owners[minionId]) > 1 {
			findings.fail("", fmt.Sprintf("minion id %s is used by %s", minionId, strings.Join(owners[minionId], ", ")), owners[minionId]...)
		}
	}
	return findings.result(id, "minion ids are unique and match the FQDN")
}

// sharesAddress tells whether the two lists have an IP address in common, whatever its notation.
func sharesAddress(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
			if ipX, ipY := net.ParseIP(x), net.ParseIP(y); ipX != nil && ipX.Equal(ipY) {
				return true
			}
		}
	}
	return false
}

func checkHostResolution(nodes []NodeDiagnostics) DiagnosticsCheck {
	const id = "host-resolution"
	var findings checkFindings
	hosts := 0
	for _, node := range nodes {
		host := node.Host
		if host == nil {
			continue
		}
		hosts++
		switch {
		case host.Fqdn == "" && strings.Contains(host.Error, "fqdn: "):
			_, text, _ := strings.Cut(host.Error, "fqdn: ")
			text, _, _ = strings.Cut(text, "; ")
			findings.fail(node.Address, "hostname -f failed: "+shortText(text))
		case host.FqdnError != "":
			findings.fail(node.Address, fmt.Sprintf("FQDN %s does not resolve: %s", host.Fqdn, shortText(host.FqdnError)))
		case host.Fqdn != "" && len(host.Addresses) > 0 && !sharesAddress(host.FqdnAddresses, host.Addresses):
			findings.fail(node.Address, fmt.Sprintf("FQDN %s resolves to [%s], not to an address of the node [%s]",
				host.Fqdn, strings.Join(host.FqdnAddresses, ","), strings.Join(host.Addresses, ",")))
		}
		// a failed hostname -f leaves Fqdn empty and is reported above
		if host.Fqdn != "" && !strings.Contains(host.Fqdn, ".") {
			findings.warn(node.Address, fmt.Sprintf("hostname -f returns the short name %s; the node may register with its short hostname", host.Fqdn))
		}
		if host.HostsMissingTrailingNewline {
			findings.warn(node.Address, "/etc/hosts has no trailing newline")
		}
	}
	if hosts == 0 {
		return skippedDiagnosticsCheck(id, "no host data")
	}
	return findings.result(id, "FQDNs resolve to the nodes")
}

// compareSaltVersions compares dotted versions numerically, so 3006.10 is newer than 3006.9. A suffix such as
// the rc1 of 3006.0rc1 is ignored. ok is false when one of the versions starts with no number.
func compareSaltVersions(a, b string) (result int, ok bool) {
	parse := func(version string) []int {
		var parts []int
		for _, part := range strings.Split(version, ".") {
			digits := part[:len(part)-len(strings.TrimLeft(part, "0123456789"))]
			number, err := strconv.Atoi(digits)
			if err != nil {
				break
			}
			parts = append(parts, number)
		}
		return parts
	}
	partsA, partsB := parse(a), parse(b)
	if len(partsA) == 0 || len(partsB) == 0 {
		return 0, false
	}
	for i := 0; i < max(len(partsA), len(partsB)); i++ {
		var x, y int
		if i < len(partsA) {
			x = partsA[i]
		}
		if i < len(partsB) {
			y = partsB[i]
		}
		if x != y {
			return x - y, true
		}
	}
	return 0, true
}

func checkSaltVersion(nodes, masters []NodeDiagnostics) DiagnosticsCheck {
	const id = "salt-version"
	var findings checkFindings
	byVersion := map[string][]string{}
	var versions []string
	for _, node := range nodes {
		if node.Minion == nil || node.Minion.SaltVersion == "" {
			continue
		}
		version := node.Minion.SaltVersion
		if _, known := byVersion[version]; !known {
			versions = append(versions, version)
		}
		byVersion[version] = append(byVersion[version], node.Address)

		var older []string
		for _, master := range masters {
			if result, ok := compareSaltVersions(version, master.Master.SaltVersion); ok && result > 0 {
				older = append(older, fmt.Sprintf("%s (%s)", master.Address, master.Master.SaltVersion))
			}
		}
		if len(older) > 0 {
			findings.fail(node.Address, fmt.Sprintf("minion %s is newer than the salt-master %s", version, strings.Join(older, ", ")))
		}
	}
	if len(versions) == 0 {
		return skippedDiagnosticsCheck(id, "no salt version reported")
	}
	if len(versions) > 1 {
		var groups []string
		for _, version := range versions {
			groups = append(groups, fmt.Sprintf("%s (%s)", version, strings.Join(byVersion[version], ", ")))
		}
		var all []string
		for _, version := range versions {
			all = append(all, byVersion[version]...)
		}
		findings.warn("", "mixed minion versions: "+strings.Join(groups, ", "), all...)
	}
	return findings.result(id, "salt versions are consistent")
}

// modeWiderThan tells whether the octal mode of a file has a permission bit outside of allowed set.
func modeWiderThan(mode string, allowed uint64) bool {
	bits, err := strconv.ParseUint(mode, 8, 32)
	return err == nil && bits&^allowed != 0
}

// modeLacks tells whether the octal mode of a file misses one of the required permission bits.
func modeLacks(mode string, required uint64) bool {
	bits, err := strconv.ParseUint(mode, 8, 32)
	return err == nil && bits&required != required
}

// checkSaltUser looks at the account salt-api authenticates against, which only salt-master nodes run.
func checkSaltUser(masters []NodeDiagnostics) DiagnosticsCheck {
	const id = "salt-user"
	if len(masters) == 0 {
		return skippedDiagnosticsCheck(id, "no salt-master among the targets")
	}
	var findings checkFindings
	for _, master := range masters {
		user := master.SaltUser
		if user == nil && slices.Contains(master.TimedOutProbes, "saltUser") {
			findings.warn(master.Address, "saltUser probe timed out")
			continue
		}
		if user != nil && !user.Present && user.Error != "" {
			findings.fail(master.Address, "saltuser entry not readable in /etc/shadow: "+shortText(user.Error))
			continue
		}
		if user == nil || !user.Present {
			findings.fail(master.Address, "saltuser has no entry in /etc/shadow")
			continue
		}
		if user.Locked {
			findings.fail(master.Address, "account locked")
		}
		if user.EmptyPassword {
			findings.fail(master.Address, "empty password")
		}
		if user.PasswordExpired {
			findings.fail(master.Address, "password expired "+user.PasswordExpiresAt)
		} else if days := user.DaysUntilPasswordExpiry; days != nil && *days < diagConfig().PasswordExpiryWarnDays {
			findings.warn(master.Address, fmt.Sprintf("password expires in %d days, on %s", *days, user.PasswordExpiresAt))
		}
		if user.AccountExpired {
			findings.fail(master.Address, "account expired "+user.AccountExpiresAt)
		}
		if user.PasswordChangeRequired {
			findings.fail(master.Address, "password change required at the next login")
		}
		if user.FaillockFailures != nil && *user.FaillockFailures > 0 {
			findings.warn(master.Address, fmt.Sprintf("%d failed logins held by faillock", *user.FaillockFailures))
		}
		switch user.PasswordCheck {
		case "mismatch":
			findings.fail(master.Address, "password does not match")
		case "unverifiable":
			findings.warn(master.Address, fmt.Sprintf("password cannot be checked: %s hash, which salt-bootstrap does not write", user.PasswordHashScheme))
		}
		if user.ShadowNewLeftover {
			findings.warn(master.Address, "/etc/shadow.new left over from an interrupted password change")
		}
		for _, file := range user.Files {
			switch {
			case file.Path == "/etc/shadow" && modeWiderThan(file.Mode, diagnosticsShadowMaxMode):
				findings.warn(master.Address, fmt.Sprintf("/etc/shadow mode %s is wider than %04o", file.Mode, diagnosticsShadowMaxMode))
			case (file.Path == "/etc/passwd" || file.Path == "/etc/group") && modeLacks(file.Mode, diagnosticsReadableMode):
				findings.warn(master.Address, fmt.Sprintf("%s mode %s is not world-readable", file.Path, file.Mode))
			}
		}
	}
	return findings.result(id, "saltuser account is usable")
}

// formatAge writes seconds as hours and minutes, e.g. 2h3m.
func formatAge(seconds int64) string {
	return fmt.Sprintf("%dh%dm", seconds/3600, seconds%3600/60)
}

// longRunningJobs describes the jobs older than the configured JobAgeWarn; a single job is named with its age, several
// are counted and the oldest ones listed.
func longRunningJobs(kind string, jobs []SaltJobDiagnostics) (text string, found bool) {
	var old []SaltJobDiagnostics
	for _, job := range jobs {
		if job.AgeSeconds != nil && *job.AgeSeconds > int64(diagConfig().JobAgeWarn.Seconds()) {
			old = append(old, job)
		}
	}
	switch len(old) {
	case 0:
		return "", false
	case 1:
		return fmt.Sprintf("%s job %s running for %s", kind, old[0].Jid, formatAge(*old[0].AgeSeconds)), true
	}
	var items []string
	for _, job := range old {
		items = append(items, fmt.Sprintf("%s (%s)", job.Jid, formatAge(*job.AgeSeconds)))
	}
	return fmt.Sprintf("%d %s jobs running for over %s: %s", len(old), kind, formatAge(int64(diagConfig().JobAgeWarn.Seconds())), limitedList(items)), true
}

// checkSaltJobs warns about salt jobs that run for more than the configured JobAgeWarn, which usually means a hung
// salt-minion or a state that never returns, and about a salt-master with more minions than its worker threads
// serve. It never fails: a long job may be expected, e.g. a long highstate.
func checkSaltJobs(nodes, masters []NodeDiagnostics) DiagnosticsCheck {
	const id = "salt-jobs"
	var findings checkFindings
	reported := false
	for _, node := range nodes {
		if node.Jobs == nil {
			continue
		}
		reported = true
		if text, found := longRunningJobs("minion", node.Jobs.MinionJobs); found {
			findings.warn(node.Address, text)
		}
		if text, found := longRunningJobs("master", node.Jobs.MasterJobs); found {
			findings.warn(node.Address, text)
		}
	}
	for _, master := range masters {
		if master.Jobs == nil || master.Master == nil {
			continue
		}
		accepted := 0
		for _, minion := range master.Master.Minions {
			if minion.KeyState == "accepted" {
				accepted++
			}
		}
		workerThreads := diagConfig().DefaultWorkerThreads
		if master.Jobs.WorkerThreads != nil {
			workerThreads = *master.Jobs.WorkerThreads
		}
		if accepted > workerThreads*diagConfig().MinionsPerWorkerThread {
			findings.warn(master.Address, fmt.Sprintf("worker_threads is %d for %d accepted minions; the master may time out under load", workerThreads, accepted))
		}
	}
	if !reported {
		return skippedDiagnosticsCheck(id, "no job data")
	}
	return findings.result(id, "no long-running salt jobs")
}

// checkClock warns about a node whose clock is not NTP synchronized and compares the clocks of the nodes with their
// median (the upper-middle one for an even count). The comparison needs two nodes. Kerberos, which the nodes of a cluster authenticate with, rejects a skew over
// 5 minutes.
func checkClock(nodes []NodeDiagnostics) DiagnosticsCheck {
	const id = "clock"
	var findings checkFindings
	reported := false
	type nodeTime struct {
		address string
		unix    int64
	}
	var times []nodeTime
	for _, node := range nodes {
		clock := node.Time
		if clock == nil {
			continue
		}
		reported = true
		if clock.NtpSynchronized != nil && !*clock.NtpSynchronized {
			if clock.NtpEnabled != nil && !*clock.NtpEnabled {
				findings.warn(node.Address, "NTP is disabled")
			} else {
				findings.warn(node.Address, "clock is not NTP synchronized")
			}
		}
		// Now is written by the time probe in UTC, RFC3339, with the second resolution
		// a node contacted later was asked for its time later, which is no skew of its clock
		if now, err := time.Parse(time.RFC3339, clock.Now); err == nil {
			times = append(times, nodeTime{node.Address, now.Unix() - int64(node.contactOffset/time.Second)})
		}
	}
	if !reported {
		return skippedDiagnosticsCheck(id, "no time reported")
	}
	if len(times) >= 2 {
		sorted := slices.SortedFunc(slices.Values(times), func(a, b nodeTime) int { return cmp.Compare(a.unix, b.unix) })
		// with an even count the upper-middle node's own time is the reference, so two nodes are compared by their full skew
		median := sorted[len(sorted)/2].unix
		for _, t := range times {
			skew := time.Duration(t.unix-median) * time.Second
			direction := "ahead of"
			if skew < 0 {
				skew, direction = -skew, "behind"
			}
			text := fmt.Sprintf("clock is %s %s the median of the nodes", skew, direction)
			switch {
			case skew > diagConfig().ClockSkewFail:
				findings.fail(t.address, text+"; Kerberos rejects skew over 5 minutes")
			case skew > diagConfig().ClockSkewWarn:
				findings.warn(t.address, text)
			}
		}
	}
	return findings.result(id, "clocks are NTP synchronized and agree")
}

// lowFree reports a filesystem that has less than the configured LowFreeWarnPercent of its space or inodes left.
func (f *checkFindings) lowFree(address, what string, free, total *uint64) {
	if free == nil || total == nil || *total == 0 {
		return
	}
	percent := float64(*free) / float64(*total) * 100
	text := fmt.Sprintf("%s %.1f%% left", what, percent)
	switch {
	case percent < diagConfig().LowFreeFailPercent:
		f.fail(address, text)
	case percent < diagConfig().LowFreeWarnPercent:
		f.warn(address, text)
	}
}

func (f *checkFindings) filesystem(address, path string, fs FilesystemDiagnostics) {
	f.lowFree(address, path+" space", fs.AvailableBytes, fs.TotalBytes)
	f.lowFree(address, path+" inodes", fs.FreeInodes, fs.TotalInodes)
}

func checkResources(nodes []NodeDiagnostics) DiagnosticsCheck {
	const id = "resources"
	var findings checkFindings
	reported := false
	for _, node := range nodes {
		resources := node.Resources
		if resources == nil {
			continue
		}
		reported = true
		seen := map[string]bool{}
		if disk := resources.Disk; disk != nil {
			if disk.Root != nil {
				seen["/"] = true
				findings.filesystem(node.Address, "/", *disk.Root)
			}
			for _, mount := range disk.Mounts {
				seen[mount.Path] = true
				findings.filesystem(node.Address, mount.Path, mount.FilesystemDiagnostics)
			}
			if disk.Lvm != nil {
				for _, lv := range disk.Lvm.LogicalVolumes {
					// the usage of a logical volume was read from its first mount point, which the mounts may have covered
					if len(lv.MountPoints) > 0 && !seen[lv.MountPoints[0]] {
						seen[lv.MountPoints[0]] = true
						findings.lowFree(node.Address, lv.MountPoints[0]+" space", lv.FsAvailableBytes, lv.FsTotalBytes)
						findings.lowFree(node.Address, lv.MountPoints[0]+" inodes", lv.FsFreeInodes, lv.FsTotalInodes)
					}
				}
			}
		}
		if memory := resources.Memory; memory != nil && memory.OomKills != nil && *memory.OomKills > 0 {
			findings.warn(node.Address, fmt.Sprintf("%d processes killed by the OOM killer since boot", *memory.OomKills))
		}
		if load := resources.Load; load != nil && load.Load5PerCpu != nil && *load.Load5PerCpu > diagConfig().LoadPerCpuWarn {
			findings.warn(node.Address, fmt.Sprintf("load5 per CPU is %.2f", *load.Load5PerCpu))
		}
	}
	if !reported {
		return skippedDiagnosticsCheck(id, "no resource data")
	}
	return findings.result(id, "disk, inodes, memory and load are fine")
}
