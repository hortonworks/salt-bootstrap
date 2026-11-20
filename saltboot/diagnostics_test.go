package saltboot

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func writeTestFile(t *testing.T, baseDir, path, content string) {
	t.Helper()
	file := filepath.Join(baseDir, path)
	if err := os.MkdirAll(filepath.Dir(file), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func withoutLvmTools(t *testing.T) {
	t.Helper()
	originalLookPath := lookPath
	t.Cleanup(func() { lookPath = originalLookPath })
	lookPath = func(file string) (string, error) { return "", errors.New("not found") }
}

// mockCommands answers the commands that start with a key of outputs and fails the ones that start with a failing
// prefix, for both ExecCmd and ExecCmdWithTimeout. The longest matching prefix wins, so "hostname" and "hostname -f"
// can both be given.
func mockCommands(t *testing.T, outputs map[string]string, failing ...string) {
	t.Helper()
	originalExec := commandExecutor
	originalTimedExec := timedCommandExecutor
	originalStat := stat
	t.Cleanup(func() { commandExecutor = originalExec; timedCommandExecutor = originalTimedExec; stat = originalStat })
	withoutLvmTools(t)
	stat = initOk
	run := func(executable string, args ...string) ([]byte, error) {
		command := strings.TrimSpace(executable + " " + strings.Join(args, " "))
		for _, f := range failing {
			if strings.HasPrefix(command, f) {
				return []byte("failed"), errors.New("exit status 1")
			}
		}
		longest, found := "", false
		for prefix := range outputs {
			if strings.HasPrefix(command, prefix) && (!found || len(prefix) > len(longest)) {
				longest, found = prefix, true
			}
		}
		if !found {
			return nil, fmt.Errorf("unexpected command: %s", command)
		}
		return []byte(outputs[longest]), nil
	}
	commandExecutor = run
	timedCommandExecutor = func(timeout time.Duration, executable string, args ...string) ([]byte, error) {
		return run(executable, args...)
	}
}

// requestWithLogLines is a request for the given number of log lines and nothing else.
func requestWithLogLines(lines int) DiagnosticsRequest {
	return DiagnosticsRequest{LogLines: &lines}
}

func unitNames(units []UnitDiagnostics) string {
	var names []string
	for _, unit := range units {
		names = append(names, unit.Name)
	}
	return strings.Join(names, ",")
}

func logPaths(logs []LogDiagnostics) string {
	var paths []string
	for _, l := range logs {
		paths = append(paths, l.Path)
	}
	return strings.Join(paths, ",")
}

func findLog(t *testing.T, logs []LogDiagnostics, path string) LogDiagnostics {
	t.Helper()
	for _, l := range logs {
		if l.Path == path {
			return l
		}
	}
	t.Fatalf("log %s not found in %+v", path, logs)
	return LogDiagnostics{}
}

func TestProbeUnitsParsesSystemctlShow(t *testing.T) {
	mockCommands(t, map[string]string{
		"/bin/systemctl show salt-bootstrap": "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=0\n",
		"/bin/systemctl show salt-minion":    "LoadState=loaded\nActiveState=activating\nSubState=auto-restart\nActiveEnterTimestamp=Thu 2026-11-12 10:00:00 UTC\nNRestarts=7\nMainPID=0\n",
		"/bin/systemctl show salt-master":    "LoadState=not-found\nActiveState=inactive\nSubState=dead\n",
		"/bin/systemctl show salt-api":       "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=1234\n",
	})

	units := probeUnits(t.TempDir(), nil, testTimeouts())

	if unitNames(units) != "salt-api,salt-bootstrap,salt-minion" {
		t.Fatalf("expected salt-api, salt-bootstrap and salt-minion only, got %+v", units)
	}
	if bootstrap := units[1]; bootstrap.ActiveState != "active" || bootstrap.SubState != "running" {
		t.Errorf("unexpected salt-bootstrap state: %+v", bootstrap)
	}
	minion := units[2]
	if minion.Name != "salt-minion" || minion.ActiveState != "activating" || minion.SubState != "auto-restart" {
		t.Errorf("unexpected minion state: %+v", minion)
	}
	if minion.NRestarts == nil || *minion.NRestarts != 7 {
		t.Errorf("expected 7 restarts, got %v", minion.NRestarts)
	}
	api := units[0]
	if api.Name != "salt-api" || api.NRestarts != nil || api.MainPid == nil || *api.MainPid != 1234 {
		t.Errorf("unexpected salt-api state: %+v", api)
	}
}

func TestProbeUnitsReportsCommandFailure(t *testing.T) {
	mockCommands(t, map[string]string{
		"/bin/systemctl show salt-bootstrap": "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=0\n",
		"/bin/systemctl show salt-master":    "LoadState=not-found\n",
		"/bin/systemctl show salt-api":       "LoadState=not-found\n",
	}, "/bin/systemctl show salt-minion")

	units := probeUnits(t.TempDir(), nil, testTimeouts())

	if unitNames(units) != "salt-bootstrap,salt-minion" || units[1].Error == "" {
		t.Errorf("expected an error for salt-minion, got %+v", units)
	}
}

func TestProbeUnitsUnsupportedInitSystem(t *testing.T) {
	originalStat := stat
	defer func() { stat = originalStat }()
	stat = initError

	units := probeUnits(t.TempDir(), nil, testTimeouts())

	if len(units) != 1 || units[0].Error != "unsupported init system" {
		t.Errorf("expected unsupported init system, got %+v", units)
	}
}

func TestProbeMinion(t *testing.T) {
	baseDir := t.TempDir()
	writeTestFile(t, baseDir, "/etc/salt/minion.d/master.conf", "master:\n- 10.0.0.1\n- 10.0.0.2\n")
	writeTestFile(t, baseDir, "/etc/salt/minion.d/minion_id.conf", "id: node1.example.com\n")
	writeTestFile(t, baseDir, "/etc/salt/minion_id", "node1.old.example.com\n")

	minion := probeMinion(baseDir)

	if len(minion.Masters) != 2 || minion.Masters[0].Id != "10.0.0.1" || minion.Masters[1].Id != "10.0.0.2" || minion.Masters[0].Ports != nil {
		t.Errorf("unexpected masters: %+v", minion.Masters)
	}
	if minion.IdConfig != "node1.example.com" || minion.CachedId != "node1.old.example.com" {
		t.Errorf("unexpected ids: %+v", minion)
	}
	// there is no minion key in the temp dir, so only the fingerprints are reported as missing
	if !strings.HasPrefix(minion.Error, "fingerprint: ") || !strings.HasSuffix(minion.Error, "; minion_master.pub: missing") || minion.Fingerprint != "" {
		t.Errorf("expected only a fingerprint and a minion_master.pub error, got %q", minion.Error)
	}
}

func TestProbeMinionMissingFiles(t *testing.T) {
	minion := probeMinion(t.TempDir())

	if minion.Masters != nil || minion.IdConfig != "" || minion.CachedId != "" {
		t.Errorf("expected empty minion section, got %+v", minion)
	}
	if !strings.Contains(minion.Error, "master.conf: missing or empty") {
		t.Errorf("expected master.conf error, got %q", minion.Error)
	}
}

func TestProbeMasterPorts(t *testing.T) {
	originalDial := dialTimeout
	defer func() { dialTimeout = originalDial }()
	dialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		if address == "10.0.0.1:4506" {
			return nil, errors.New("connection refused")
		}
		client, server := net.Pipe()
		server.Close()
		return client, nil
	}

	masters := []MinionMasterDiagnostics{{Id: "10.0.0.1"}, {Id: "10.0.0.2"}}
	probeMasterPorts(masters, testTimeouts())

	if masters[0].Id != "10.0.0.1" || len(masters[0].Ports) != 2 || len(masters[1].Ports) != 2 {
		t.Fatalf("expected 2 ports per master, got %+v", masters)
	}
	if ports := masters[0].Ports; ports[0].Port != 4505 || !ports[0].Reachable || ports[0].Error != "" {
		t.Errorf("expected 10.0.0.1:4505 to be reachable, got %+v", ports[0])
	}
	if ports := masters[0].Ports; ports[1].Port != 4506 || ports[1].Reachable || ports[1].Error != "connection refused" {
		t.Errorf("expected 10.0.0.1:4506 to be refused, got %+v", ports[1])
	}
	if ports := masters[1].Ports; !ports[0].Reachable || !ports[1].Reachable {
		t.Errorf("expected both ports of 10.0.0.2 to be reachable, got %+v", ports)
	}
}

func TestDiagnosticsJsonNestsPortsUnderMasters(t *testing.T) {
	minion := MinionDiagnostics{Masters: []MinionMasterDiagnostics{{Id: "10.84.134.200", Ports: []PortDiagnostics{{Port: 4505, Reachable: true}}}}}

	b, _ := json.Marshal(minion)

	if string(b) != `{"masters":[{"id":"10.84.134.200","ports":[{"port":4505,"reachable":true}]}]}` {
		t.Errorf("unexpected json: %s", b)
	}
}

func TestProbeTime(t *testing.T) {
	mockCommands(t, map[string]string{"timedatectl show": "NTP=yes\nNTPSynchronized=no\n"})

	result := probeTime(testTimeouts())

	if result.NtpEnabled == nil || !*result.NtpEnabled || result.NtpSynchronized == nil || *result.NtpSynchronized {
		t.Errorf("unexpected time result: %+v", result)
	}
	if _, err := time.Parse(time.RFC3339, result.Now); err != nil {
		t.Errorf("now is not RFC3339: %s", result.Now)
	}
}

func TestProbeTimeFallsBackToStatus(t *testing.T) {
	mockCommands(t, map[string]string{
		"timedatectl status": "      Local time: Thu 2026-11-12 10:00:00 UTC\n     NTP enabled: yes\nNTP synchronized: yes\n",
	}, "timedatectl show")

	result := probeTime(testTimeouts())

	if result.Error != "" || result.NtpEnabled == nil || !*result.NtpEnabled || result.NtpSynchronized == nil || !*result.NtpSynchronized {
		t.Errorf("unexpected time result: %+v", result)
	}
}

func TestProbeJobs(t *testing.T) {
	// the job ids are in the local time of the node, the clock is two hours and three minutes after the first job
	withClock(t, time.Date(2026, 11, 18, 12, 18, 0, 123456000, time.Local))
	baseDir := t.TempDir()
	writeTestFile(t, baseDir, "/var/cache/salt/minion/proc/20261118101500123456", "")
	writeTestFile(t, baseDir, "/var/cache/salt/minion/proc/20261118121700000000", "")
	writeTestFile(t, baseDir, "/var/cache/salt/minion/proc/not-a-jid", "")
	writeTestFile(t, baseDir, "/var/cache/salt/minion/proc/20261399101500123456", "")
	writeTestFile(t, baseDir, "/var/cache/salt/master/proc/20261118111500000000", "")
	writeTestFile(t, baseDir, "/etc/salt/master", "interface: 0.0.0.0\nworker_threads: 5\n# worker_threads: 99\n")
	writeTestFile(t, baseDir, "/etc/salt/master.d/10-first.conf", "worker_threads: 8\n")
	writeTestFile(t, baseDir, "/etc/salt/master.d/20-second.conf", "worker_threads:   16\n")
	writeTestFile(t, baseDir, "/etc/salt/master.d/30-ignored.txt", "worker_threads: 64\n")

	jobs := probeJobs(baseDir)

	if jobs.Error != "" || jobs.MinionJobsOmitted != 0 || jobs.MasterJobsOmitted != 0 {
		t.Errorf("unexpected jobs: %+v", jobs)
	}
	started := time.Date(2026, 11, 18, 10, 15, 0, 0, time.Local)
	expected := []SaltJobDiagnostics{
		{Jid: "20261118101500123456", StartedAt: started.Format(time.RFC3339), AgeSeconds: int64Ptr(7380)},
		{Jid: "20261118121700000000", StartedAt: time.Date(2026, 11, 18, 12, 17, 0, 0, time.Local).Format(time.RFC3339), AgeSeconds: int64Ptr(60)},
		{Jid: "20261399101500123456"},
		{Jid: "not-a-jid"},
	}
	if !reflect.DeepEqual(jobs.MinionJobs, expected) {
		t.Errorf("unexpected minion jobs: %+v", jobs.MinionJobs)
	}
	if len(jobs.MasterJobs) != 1 || jobs.MasterJobs[0].Jid != "20261118111500000000" || *jobs.MasterJobs[0].AgeSeconds != 3780 {
		t.Errorf("unexpected master jobs: %+v", jobs.MasterJobs)
	}
	if jobs.WorkerThreads == nil || *jobs.WorkerThreads != 16 {
		t.Errorf("expected the last worker_threads to win, got %v", jobs.WorkerThreads)
	}
}

func TestProbeJobsWithoutProcDirectoriesAndMasterConfig(t *testing.T) {
	jobs := probeJobs(t.TempDir())

	if !reflect.DeepEqual(jobs, SaltJobsDiagnostics{}) {
		t.Errorf("expected nothing without the directories, got %+v", jobs)
	}
	b, _ := json.Marshal(NodeDiagnostics{Jobs: &jobs})
	if string(b) != `{"jobs":{}}` {
		t.Errorf("unexpected json %s", b)
	}
}

func TestProbeJobsWorkerThreadsFromTheMasterConfigOnly(t *testing.T) {
	baseDir := t.TempDir()
	writeTestFile(t, baseDir, "/etc/salt/master", "worker_threads: 12\n")
	writeTestFile(t, baseDir, "/etc/salt/master.d/api.conf", "rest_cherrypy:\n  port: 8000\n")

	if jobs := probeJobs(baseDir); jobs.WorkerThreads == nil || *jobs.WorkerThreads != 12 {
		t.Errorf("unexpected worker threads: %+v", jobs)
	}

	// a configuration without the setting leaves it unset, for the check to use the default
	writeTestFile(t, baseDir, "/etc/salt/master", "interface: 0.0.0.0\n")
	if jobs := probeJobs(baseDir); jobs.WorkerThreads != nil || jobs.Error != "" {
		t.Errorf("unexpected worker threads: %+v", jobs)
	}
}

func TestProbeJobsCapsTheJobLists(t *testing.T) {
	withClock(t, time.Date(2026, 11, 18, 12, 0, 0, 0, time.Local))
	baseDir := t.TempDir()
	for i := 0; i < diagConfig().MaxJobs+7; i++ {
		writeTestFile(t, baseDir, fmt.Sprintf("/var/cache/salt/minion/proc/20261118%06d000000", i), "")
	}
	for i := 0; i < diagConfig().MaxJobs; i++ {
		writeTestFile(t, baseDir, fmt.Sprintf("/var/cache/salt/master/proc/20261118%06d000000", i), "")
	}

	jobs := probeJobs(baseDir)

	if len(jobs.MinionJobs) != diagConfig().MaxJobs || jobs.MinionJobsOmitted != 7 || jobs.MinionJobs[0].Jid != "20261118000000000000" {
		t.Errorf("expected the oldest %d minion jobs and 7 omitted, got %d, %d omitted", diagConfig().MaxJobs, len(jobs.MinionJobs), jobs.MinionJobsOmitted)
	}
	if len(jobs.MasterJobs) != diagConfig().MaxJobs || jobs.MasterJobsOmitted != 0 {
		t.Errorf("expected all master jobs, got %d, %d omitted", len(jobs.MasterJobs), jobs.MasterJobsOmitted)
	}
}

func TestProbeJobsReportsAnUnreadableProcDirectory(t *testing.T) {
	baseDir := t.TempDir()
	// a file where the directory should be
	writeTestFile(t, baseDir, "/var/cache/salt/minion/proc", "")

	jobs := probeJobs(baseDir)

	if !strings.Contains(jobs.Error, "minion proc: ") || jobs.MinionJobs != nil {
		t.Errorf("unexpected jobs: %+v", jobs)
	}
}

func TestSaltJobAgeIsNeverNegative(t *testing.T) {
	job := saltJob("20261118120000000000", time.Date(2026, 11, 18, 11, 59, 0, 0, time.Local))

	if job.AgeSeconds == nil || *job.AgeSeconds != 0 {
		t.Errorf("unexpected job: %+v", job)
	}
}

func TestCollectDiagnosticsRecordsAPanickingJobsProbe(t *testing.T) {
	probes := []diagnosticsProbe{
		{"jobs", func() func(*NodeDiagnostics) { panic("boom") }},
		{"time", func() func(*NodeDiagnostics) { return func(d *NodeDiagnostics) { d.Time = &TimeDiagnostics{} } }},
	}
	var logged bytes.Buffer
	log.SetOutput(&logged)
	defer log.SetOutput(os.Stderr)

	diagnostics := collectDiagnosticsWith(t.TempDir(), requestWithLogLines(0), probes)

	if diagnostics.Jobs != nil || diagnostics.Time == nil || strings.Join(diagnostics.FailedProbes, ",") != "jobs: boom" {
		t.Errorf("unexpected diagnostics: %+v", diagnostics)
	}
}

func TestProbeLoadMemoryAndRootFilesystem(t *testing.T) {
	baseDir := t.TempDir()
	writeTestFile(t, baseDir, "/proc/loadavg", "3.50 2.25 1.00 2/345 6789\n")
	writeTestFile(t, baseDir, "/proc/meminfo", "MemTotal:        8000000 kB\nMemFree:          100000 kB\nMemAvailable:     250000 kB\n")
	writeTestFile(t, baseDir, "/proc/cpuinfo", "processor\t: 0\nmodel name\t: x\n\nprocessor\t: 1\nmodel name\t: x\n\nprocessor\t: 2\n\nprocessor\t: 3\n")
	writeTestFile(t, baseDir, "/proc/vmstat", "nr_free_pages 12345\noom_kill 3\npgfault 99\n")

	load, memory, root := probeLoad(baseDir), probeMemory(baseDir), probeRootFilesystem(baseDir)

	if load.Error != "" || memory.Error != "" || root.Error != "" {
		t.Errorf("unexpected errors: %q %q %q", load.Error, memory.Error, root.Error)
	}
	if *load.Load1 != 3.5 || *load.Load5 != 2.25 || *load.Load15 != 1 {
		t.Errorf("unexpected load: %v %v %v", *load.Load1, *load.Load5, *load.Load15)
	}
	if load.CpuCount != 4 || *load.Load1PerCpu != 0.88 || *load.Load5PerCpu != 0.56 || *load.Load15PerCpu != 0.25 {
		t.Errorf("unexpected per-cpu load: %d %v %v %v", load.CpuCount, *load.Load1PerCpu, *load.Load5PerCpu, *load.Load15PerCpu)
	}
	if *memory.TotalKb != 8000000 || *memory.AvailableKb != 250000 {
		t.Errorf("unexpected memory: %d %d", *memory.TotalKb, *memory.AvailableKb)
	}
	if root.TotalBytes == nil || *root.TotalBytes == 0 || root.AvailableBytes == nil {
		t.Errorf("expected filesystem sizes, got %+v", root)
	}
}

func TestProbeLoadAndMemoryMissingProc(t *testing.T) {
	baseDir := t.TempDir()

	load, memory := probeLoad(baseDir), probeMemory(baseDir)

	if !strings.HasPrefix(load.Error, "loadavg: ") || !strings.HasPrefix(memory.Error, "meminfo: ") {
		t.Errorf("expected loadavg and meminfo errors, got %q %q", load.Error, memory.Error)
	}
	if load.CpuCount != runtime.NumCPU() || load.Load1PerCpu != nil {
		t.Errorf("expected the runtime cpu count and no per-cpu load, got %d %v", load.CpuCount, load.Load1PerCpu)
	}
	if root := probeRootFilesystem(baseDir); root.Error != "" || root.TotalBytes == nil {
		t.Errorf("the root filesystem probe should still succeed, got %+v", root)
	}
}

func TestCollectDiagnosticsGroupsResources(t *testing.T) {
	mockCommands(t, map[string]string{"/bin/systemctl show": "LoadState=loaded\n", "timedatectl show": "NTP=yes\n"})
	// mockCommands hides the LVM tools, so bring them back for this test
	mockLvm(t, map[string]string{"lvs": testLvsOutput, "vgs": testVgsOutput}, nil)
	baseDir := t.TempDir()
	writeTestFile(t, baseDir, "/proc/loadavg", "1.00 1.00 1.00 1/1 1\n")
	writeTestFile(t, baseDir, "/proc/meminfo", "MemTotal: 100 kB\nMemAvailable: 50 kB\n")
	writeTestFile(t, baseDir, "/proc/self/mounts", "")

	diagnostics := collectDiagnostics(baseDir, requestWithLogLines(0))

	resources := diagnostics.Resources
	if resources == nil || resources.Load == nil || resources.Memory == nil || resources.Disk == nil {
		t.Fatalf("expected load, memory and disk, got %+v", resources)
	}
	if resources.Disk.Root == nil || resources.Disk.Lvm == nil || len(resources.Disk.Lvm.LogicalVolumes) != 5 {
		t.Errorf("expected the root filesystem and lvm under disk, got %+v", resources.Disk)
	}

	b, _ := json.Marshal(resources)
	for _, key := range []string{`"load":{`, `"memory":{`, `"disk":{"root":{`, `"lvm":{"volumeGroups":`} {
		if !strings.Contains(string(b), key) {
			t.Errorf("expected %s in %s", key, b)
		}
	}
}

func TestResourcesSettersDoNotOverwriteEachOther(t *testing.T) {
	lvm := &LvmDiagnostics{Error: "lvs: timed out after 5s"}
	load, memory, root := LoadDiagnostics{CpuCount: 2}, MemoryDiagnostics{}, FilesystemDiagnostics{}

	// lvm finishing before the resources probe must survive the resources setter, and the other way round
	lvmFirst, resourcesFirst := &NodeDiagnostics{}, &NodeDiagnostics{}
	lvmFirst.setLvm(lvm)
	lvmFirst.setLoadMemoryAndRoot(&load, &memory, &root)
	resourcesFirst.setLoadMemoryAndRoot(&load, &memory, &root)
	resourcesFirst.setLvm(lvm)

	for _, d := range []*NodeDiagnostics{lvmFirst, resourcesFirst} {
		if d.Resources.Load.CpuCount != 2 || d.Resources.Disk.Root == nil || d.Resources.Disk.Lvm != lvm {
			t.Errorf("a setter overwrote the other: %+v", d.Resources)
		}
	}

	withoutLvm := &NodeDiagnostics{}
	withoutLvm.setLvm(nil)
	if withoutLvm.Resources != nil {
		t.Errorf("expected no resources for a node without LVM tools, got %+v", withoutLvm.Resources)
	}
}

func TestTailLogReturnsLastLines(t *testing.T) {
	baseDir := t.TempDir()
	writeTestFile(t, baseDir, "/var/log/salt/minion", "line1\nline2\nline3\nline4\n")

	result := tailLog(baseDir+"/var/log/salt/minion", "/var/log/salt/minion", 2)

	if strings.Join(result.Lines, ",") != "line3,line4" || !result.Truncated || result.Error != "" {
		t.Errorf("unexpected tail: %+v", result)
	}
}

func TestTailLogReadsOnlyTheEndOfLargeFiles(t *testing.T) {
	baseDir := t.TempDir()
	var content strings.Builder
	for i := 0; content.Len() < 3*diagConfig().LogWindowBytes; i++ {
		fmt.Fprintf(&content, "log line number %d\n", i)
	}
	writeTestFile(t, baseDir, "/big.log", content.String())

	result := tailLog(baseDir+"/big.log", "/big.log", diagConfig().MaxLogLines)

	if len(result.Lines) != diagConfig().MaxLogLines || !result.Truncated {
		t.Fatalf("expected %d truncated lines, got %d", diagConfig().MaxLogLines, len(result.Lines))
	}
	allLines := strings.Split(strings.TrimSpace(content.String()), "\n")
	if result.Lines[len(result.Lines)-1] != allLines[len(allLines)-1] {
		t.Errorf("expected the last line, got %s", result.Lines[len(result.Lines)-1])
	}
	for _, line := range result.Lines {
		if !strings.HasPrefix(line, "log line number ") {
			t.Errorf("partial line returned: %q", line)
		}
	}
}

func TestTailLogMissingFile(t *testing.T) {
	result := tailLog(t.TempDir()+"/missing.log", "/missing.log", 10)

	if result.Error == "" || len(result.Lines) != 0 {
		t.Errorf("expected an error, got %+v", result)
	}
}

func TestTailLogCapsLongLines(t *testing.T) {
	baseDir := t.TempDir()
	writeTestFile(t, baseDir, "/long.log", strings.Repeat("x", 5000)+"\n")

	result := tailLog(baseDir+"/long.log", "/long.log", 10)

	if len(result.Lines) != 1 || len(result.Lines[0]) != diagConfig().MaxLineBytes+len("...[truncated]") {
		t.Errorf("expected a capped line, got %d bytes", len(result.Lines[0]))
	}
}

func TestRedactLine(t *testing.T) {
	cases := map[string]string{
		`password=s3cr3t other=1`:                      `password=*** other=1`,
		`{"password":"s3cr3t","user":"cbadmin"}`:       `{"password":"***","user":"cbadmin"}`,
		`signature: abcDEF123==`:                       `signature: ***`,
		`Authorization: Basic Y2JhZG1pbjpzM2NyM3Q=`:    `Authorization: Basic ***`,
		`token = xyz`:                                  `token = ***`,
		`[INFO] Executing state test.ping for [node1]`: `[INFO] Executing state test.ping for [node1]`,
	}
	for input, expected := range cases {
		if actual := redactLine(input); actual != expected {
			t.Errorf("redactLine(%q) = %q, expected %q", input, actual, expected)
		}
	}
}

func TestRedactLineKeysAndSeparators(t *testing.T) {
	cases := []struct{ input, expected string }{
		{`'db_password': 'hunter2'`, `'db_password': '***'`},
		{`"db_password": "hunter2", "user": "x"`, `"db_password": "***", "user": "x"`},
		{`adminPassword=hunter2`, `adminPassword=***`},
		{`aws_secret_access_key = abc`, `aws_secret_access_key = ***`},
		{`ldap.bind.password=hunter2`, `ldap.bind.password=***`},
		{`X-Auth-Token: abc123`, `X-Auth-Token: ***`},
		{`db_pass=hunter2 admin-pass: s3`, `db_pass=*** admin-pass: ***`},
		{`pass=hunter2`, `pass=***`},
		{`[pwd=hunter2]`, `[pwd=***]`},
		{`--password hunter2`, `--password ***`},
		{`run --db-password=hunter2 --verbose`, `run --db-password=*** --verbose`},
		{`run --db-password hunter2 --verbose`, `run --db-password *** --verbose`},
		{`--password "hunter2"`, `--password "***"`},
		{`--password --verbose`, `--password --verbose`},
		{`jdbc:postgresql://u:hunter2@db:5432/x`, `jdbc:postgresql://u:***@db:5432/x`},
		{`https://user:hunter2@host/`, `https://user:***@host/`},
		{`https://user:p@ss@host/path`, `https://user:***@host/path`},
		{`https://host:8080/path`, `https://host:8080/path`},
		{`password: hunter2`, `password: ***`},
		{`cm-password: hunter2`, `cm-password: ***`},
		{`Authorization: Basic Y2JhZG1pbjpzM2NyM3Q=`, `Authorization: Basic ***`},
		{`secret_key: "a b"`, `secret_key: "***"`},
		{`secret_key: 'pass word' next`, `secret_key: '***' next`},
		{`'db_pass': 'a b', 'x': 1`, `'db_pass': '***', 'x': 1`},
		{`{"password":"a b","user":"x"}`, `{"password":"***","user":"x"}`},
		{`--password "a b" --verbose`, `--password "***" --verbose`},
		{`--password 'a b' --verbose`, `--password '***' --verbose`},
		{`password="unterminated`, `password=***`},
		{`saltuser password expired`, `saltuser password expired`},
		{`password changed for saltuser`, `password changed for saltuser`},
		{`password expires in 3 days`, `password expires in 3 days`},
		{`token refresh scheduled`, `token refresh scheduled`},
		{`passing 3 tests`, `passing 3 tests`},
		{`bypass=false`, `bypass=false`},
		{`compass: north`, `compass: north`},
		{`pass-through enabled`, `pass-through enabled`},
	}
	for _, c := range cases {
		if actual := redactLine(c.input); actual != c.expected {
			t.Errorf("redactLine(%q) = %q, expected %q", c.input, actual, c.expected)
		}
	}
}

func TestCollectDiagnosticsReportsTimedOutProbes(t *testing.T) {
	setDiagnosticsConfig(t, func(c *DiagnosticsConfig) { c.ProbeDeadline = 200 * time.Millisecond })
	withoutLvmTools(t)

	release := make(chan struct{})
	finished := make(chan struct{})
	originalExec := commandExecutor
	originalTimedExec := timedCommandExecutor
	originalStat := stat
	// the abandoned probe still runs, so let it finish before restoring the globals it reads
	defer func() {
		close(release)
		<-finished
		commandExecutor, timedCommandExecutor, stat = originalExec, originalTimedExec, originalStat
	}()
	stat = initOk
	commandExecutor = func(executable string, args ...string) ([]byte, error) {
		return nil, errors.New("not available")
	}
	timedCommandExecutor = func(timeout time.Duration, executable string, args ...string) ([]byte, error) {
		switch executable {
		case "timedatectl":
			<-release
			defer close(finished)
		case SYSTEM_D.StateBin:
		default:
			return nil, errors.New("not available")
		}
		return []byte("LoadState=loaded\nActiveState=active\nSubState=running\n"), nil
	}

	diagnostics := collectDiagnostics(t.TempDir(), requestWithLogLines(10))

	if strings.Join(diagnostics.TimedOutProbes, ",") != "time" {
		t.Errorf("expected only the time probe to time out, got %v", diagnostics.TimedOutProbes)
	}
	if diagnostics.Time != nil || len(diagnostics.Units) == 0 || diagnostics.Minion == nil || diagnostics.Resources == nil || len(diagnostics.Logs) != 2 {
		t.Errorf("unexpected diagnostics: %+v", diagnostics)
	}
}

func TestDiagnosticsHandler(t *testing.T) {
	mockCommands(t, map[string]string{
		"/bin/systemctl show": "LoadState=loaded\nActiveState=active\nSubState=running\n",
		"timedatectl show":    "NTP=yes\nNTPSynchronized=yes\n",
	})
	baseDir := t.TempDir()
	writeTestFile(t, baseDir, "/var/log/saltboot.log", "a\nb\nc\n")

	req := httptest.NewRequest("POST", "/saltboot/diagnostics?index=0", bytes.NewBufferString(`{"logLines": 1}`))
	req.Header.Set("salt-minion-base-dir", baseDir)
	w := httptest.NewRecorder()
	DiagnosticsHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var diagnostics NodeDiagnostics
	if err := json.Unmarshal(w.Body.Bytes(), &diagnostics); err != nil {
		t.Fatal(err)
	}
	if unitNames(diagnostics.Units) != "salt-api,salt-bootstrap,salt-master,salt-minion" || diagnostics.Time == nil || !*diagnostics.Time.NtpSynchronized {
		t.Errorf("unexpected diagnostics: %+v", diagnostics)
	}
	if logPaths(diagnostics.Logs) != "/var/log/salt/minion,/var/log/saltboot.log" ||
		strings.Join(findLog(t, diagnostics.Logs, "/var/log/saltboot.log").Lines, ",") != "c" {
		t.Errorf("unexpected logs: %+v", diagnostics.Logs)
	}
}

func TestDiagnosticsHandlerAcceptsEmptyBody(t *testing.T) {
	mockCommands(t, map[string]string{"/bin/systemctl show": "LoadState=loaded\n", "timedatectl show": "NTP=yes\n"})

	req := httptest.NewRequest("POST", "/saltboot/diagnostics", nil)
	req.Header.Set("salt-minion-base-dir", t.TempDir())
	w := httptest.NewRecorder()
	DiagnosticsHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestDiagnosticsDistributeHandlerRejectsMissingTargets(t *testing.T) {
	req := httptest.NewRequest("POST", "/saltboot/diagnostics/distribute", bytes.NewBufferString(`{"targets": []}`))
	w := httptest.NewRecorder()
	DiagnosticsDistributeHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestDistributeDiagnosticsImpl(t *testing.T) {
	contacted := time.Now()
	distribute := func(targets []string, endpoint, user, pass string, body RequestBody, timeout time.Duration, maxParallel int) <-chan RawResponse {
		if maxParallel != 7 {
			t.Errorf("expected the parallelism to be passed on, got %d", maxParallel)
		}
		if endpoint != DiagnosticsEP || timeout != 5*time.Second {
			t.Errorf("unexpected endpoint %s or timeout %s", endpoint, timeout)
		}
		c := make(chan RawResponse, 4)
		c <- RawResponse{Address: "10.0.0.1:7071", ContactedAt: contacted.Add(3 * time.Second), StatusCode: 200, Body: []byte(`{"statusCode":200,"address":"ignored","units":[{"name":"salt-minion","activeState":"failed"}]}`)}
		c <- RawResponse{Address: "10.0.0.2:7071", ContactedAt: contacted, StatusCode: 500, Err: errors.New("dial tcp 10.0.0.2:7071: connect: no route to host")}
		c <- RawResponse{Address: "10.0.0.3:7071", StatusCode: 404, Body: []byte("404 page not found\n")}
		c <- RawResponse{Address: "10.0.0.4:7071", StatusCode: 200, Body: []byte("not json")}
		close(c)
		return c
	}

	nodes := distributeDiagnosticsImpl(distribute, []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"}, "user", "pass", RequestBody{}, 5*time.Second, 7)

	if len(nodes) != 4 {
		t.Fatalf("expected 4 nodes, got %d", len(nodes))
	}
	if nodes[0].Address != "10.0.0.1:7071" || nodes[0].StatusCode != 200 || nodes[0].Units[0].ActiveState != "failed" {
		t.Errorf("unexpected node 1: %+v", nodes[0])
	}
	if nodes[1].StatusCode != 500 || !strings.Contains(nodes[1].ErrorText, "no route to host") {
		t.Errorf("unexpected node 2: %+v", nodes[1])
	}
	if nodes[2].StatusCode != 404 || nodes[2].ErrorText != "unexpected response: 404 page not found" {
		t.Errorf("unexpected node 3: %+v", nodes[2])
	}
	if nodes[3].StatusCode != 500 || nodes[3].ErrorText != "unexpected response: not json" {
		t.Errorf("unexpected node 4: %+v", nodes[3])
	}
	// the offset is counted from the earliest contact of the call, and is no part of the response; targets without
	// a contact time have none
	offsets := []time.Duration{nodes[0].contactOffset, nodes[1].contactOffset, nodes[2].contactOffset, nodes[3].contactOffset}
	if !slices.Equal(offsets, []time.Duration{3 * time.Second, 0, 0, 0}) {
		t.Errorf("unexpected contact offsets %v", offsets)
	}
	if body, err := json.Marshal(nodes[0]); err != nil || strings.Contains(strings.ToLower(string(body)), "offset") {
		t.Errorf("expected no contact offset in the response, got %s, %v", body, err)
	}
	if withoutPorts(nodes)[0].contactOffset != 3*time.Second {
		t.Error("expected the contact offset to survive withoutPorts")
	}
}

func TestProbeLogsIncludesMasterAndApiLogsOnlyWhenPresent(t *testing.T) {
	baseDir := t.TempDir()
	writeTestFile(t, baseDir, "/var/log/salt/minion", "minion line\n")

	logs := probeLogs(baseDir, 10)

	if logPaths(logs) != "/var/log/salt/minion,/var/log/saltboot.log" {
		t.Fatalf("expected only the minion and saltboot logs, got %+v", logs)
	}

	writeTestFile(t, baseDir, "/var/log/salt/master", "master line\nSaltReqTimeoutError token=abc\n")

	logs = probeLogs(baseDir, 10)

	if logPaths(logs) != "/var/log/salt/master,/var/log/salt/minion,/var/log/saltboot.log" {
		t.Fatalf("expected the master log as well, got %+v", logs)
	}
	if master := findLog(t, logs, "/var/log/salt/master"); master.Error != "" || strings.Join(master.Lines, ",") != "master line,SaltReqTimeoutError token=***" {
		t.Errorf("unexpected master log: %+v", master)
	}

	writeTestFile(t, baseDir, "/var/log/salt/api", "api line\n")

	logs = probeLogs(baseDir, 10)

	if logPaths(logs) != "/var/log/salt/api,/var/log/salt/master,/var/log/salt/minion,/var/log/saltboot.log" {
		t.Fatalf("expected the api log as well, got %+v", logs)
	}
	if api := findLog(t, logs, "/var/log/salt/api"); strings.Join(api.Lines, ",") != "api line" {
		t.Errorf("unexpected api log: %+v", api)
	}
}

func TestDiagnosticsHandlerReadsSaltbootLogBeforeItsOwnLogging(t *testing.T) {
	mockCommands(t, map[string]string{"/bin/systemctl show": "LoadState=loaded\n", "timedatectl show": "NTP=yes\n"})
	baseDir := t.TempDir()
	writeTestFile(t, baseDir, "/var/log/saltboot.log", "before 1\nbefore 2\n")
	// log to the saltboot.log fixture like main does, so every line this request logs lands in it
	logFile, err := os.OpenFile(baseDir+"/var/log/saltboot.log", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	originalOutput := log.Writer()
	log.SetOutput(logFile)
	defer func() { log.SetOutput(originalOutput); logFile.Close() }()

	req := httptest.NewRequest("POST", "/saltboot/diagnostics", bytes.NewBufferString(`{"logLines": 2}`))
	req.Header.Set("salt-minion-base-dir", baseDir)
	w := httptest.NewRecorder()
	DiagnosticsHandler(w, req)

	var diagnostics NodeDiagnostics
	if err := json.Unmarshal(w.Body.Bytes(), &diagnostics); err != nil {
		t.Fatal(err)
	}
	if lines := strings.Join(findLog(t, diagnostics.Logs, "/var/log/saltboot.log").Lines, ","); lines != "before 1,before 2" {
		t.Errorf("expected only the lines logged before the request, got %q", lines)
	}
	if content, _ := os.ReadFile(baseDir + "/var/log/saltboot.log"); !strings.Contains(string(content), "[DiagnosticsHandler]") {
		t.Errorf("expected the request to log after collecting, log was %q", content)
	}
}

type lvmCall struct {
	executable string
	args       []string
	timeout    time.Duration
}

func mockLvm(t *testing.T, outputs map[string]string, failures map[string]error) *[]lvmCall {
	t.Helper()
	originalLookPath := lookPath
	originalExec := timedCommandExecutor
	t.Cleanup(func() { lookPath = originalLookPath; timedCommandExecutor = originalExec })
	lookPath = func(file string) (string, error) {
		if file == "lvs" || file == "vgs" {
			return "/usr/sbin/" + file, nil
		}
		return "", errors.New("not found")
	}
	var calls []lvmCall
	var mu sync.Mutex
	timedCommandExecutor = func(timeout time.Duration, executable string, args ...string) ([]byte, error) {
		mu.Lock()
		calls = append(calls, lvmCall{executable, args, timeout})
		mu.Unlock()
		tool := filepath.Base(executable)
		if err := failures[tool]; err != nil {
			return nil, err
		}
		return []byte(outputs[tool]), nil
	}
	return &calls
}

const testLvsOutput = `{
  "report": [{"lv": [
    {"vg_name":"rootvg", "lv_name":"root", "lv_path":"/dev/rootvg/root", "lv_size":"10737418240", "lv_attr":"-wi-ao----", "lv_active":"active", "pool_lv":"", "data_percent":"", "metadata_percent":""},
    {"vg_name":"rootvg", "lv_name":"var-log", "lv_path":"/dev/rootvg/var-log", "lv_size":"2147483648", "lv_attr":"-wi-ao----", "lv_active":"active", "pool_lv":"", "data_percent":"", "metadata_percent":""},
    {"vg_name":"rootvg", "lv_name":"home", "lv_path":"/dev/rootvg/home", "lv_size":"1073741824", "lv_attr":"Vwi-aotz--", "lv_active":"active", "pool_lv":"pool", "data_percent":"12.50", "metadata_percent":""},
    {"vg_name":"rootvg", "lv_name":"pool", "lv_path":"", "lv_size":"5368709120", "lv_attr":"twi-aotz--", "lv_active":"active", "pool_lv":"", "data_percent":"97.31", "metadata_percent":"41.02"},
    {"vg_name":"rootvg", "lv_name":"old", "lv_path":"/dev/rootvg/old", "lv_size":"1073741824", "lv_attr":"-wi-------", "lv_active":"", "pool_lv":"", "data_percent":"", "metadata_percent":""}
  ]}]
}`

const testVgsOutput = `{"report": [{"vg": [{"vg_name":"rootvg", "vg_size":"21470642176", "vg_free":"1073741824", "lv_count":"5", "pv_count":"1"}]}]}`

func TestProbeLvm(t *testing.T) {
	calls := mockLvm(t, map[string]string{"lvs": testLvsOutput, "vgs": testVgsOutput}, nil)
	baseDir := t.TempDir()
	for _, dir := range []string{"/var/log", "/home", "/mnt/my data", "/dev/mapper"} {
		if err := os.MkdirAll(baseDir+dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("../dm-1", baseDir+"/dev/mapper/rootvg-var--log"); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, baseDir, "/proc/self/mounts", strings.Join([]string{
		"/dev/mapper/rootvg-root / xfs rw,relatime 0 0",
		"proc /proc proc rw 0 0",
		"/dev/dm-1 /var/log xfs rw 0 0",
		"/dev/rootvg/home /home ext4 rw 0 0",
		"/dev/mapper/rootvg-root /mnt/my\\040data xfs rw 0 0",
		"/dev/sda1 /boot xfs rw 0 0",
	}, "\n")+"\n")

	lvm := probeLvm(baseDir, testTimeouts())

	if lvm == nil || lvm.Error != "" {
		t.Fatalf("unexpected lvm result: %+v", lvm)
	}
	if len(lvm.VolumeGroups) != 1 || *lvm.VolumeGroups[0].FreeBytes != 1073741824 || *lvm.VolumeGroups[0].LvCount != 5 {
		t.Errorf("unexpected volume groups: %+v", lvm.VolumeGroups)
	}
	if len(lvm.LogicalVolumes) != 5 {
		t.Fatalf("expected 5 logical volumes, got %+v", lvm.LogicalVolumes)
	}
	root, varLog, home, pool, old := lvm.LogicalVolumes[0], lvm.LogicalVolumes[1], lvm.LogicalVolumes[2], lvm.LogicalVolumes[3], lvm.LogicalVolumes[4]
	if strings.Join(root.MountPoints, ",") != "/,/mnt/my data" || root.FsType != "xfs" || root.FsTotalBytes == nil || *root.SizeBytes != 10737418240 {
		t.Errorf("unexpected root volume: %+v", root)
	}
	if root.Error != "" || root.FsAvailableBytes == nil {
		t.Errorf("expected the usage of the root volume, got %+v", root)
	}
	// the inodes stay unset on a filesystem that reports none, so only their pairing is stable
	if (root.FsTotalInodes == nil) != (root.FsFreeInodes == nil) {
		t.Errorf("expected total and free inodes together, got %+v", root)
	}
	if strings.Join(varLog.MountPoints, ",") != "/var/log" {
		t.Errorf("expected var-log to be matched through /dev/dm-1, got %+v", varLog)
	}
	if strings.Join(home.MountPoints, ",") != "/home" || home.FsType != "ext4" || home.Pool != "pool" || *home.DataPercent != 12.5 {
		t.Errorf("unexpected home volume: %+v", home)
	}
	if pool.MountPoints != nil || *pool.DataPercent != 97.31 || *pool.MetadataPercent != 41.02 || !pool.Active {
		t.Errorf("unexpected thin pool: %+v", pool)
	}
	if old.Active || old.MountPoints != nil || old.DataPercent != nil {
		t.Errorf("expected an inactive, unmounted volume, got %+v", old)
	}

	for _, call := range *calls {
		if call.timeout != diagConfig().LvmTimeout || strings.Join(call.args[:6], " ") != "--readonly --reportformat json --units b --nosuffix" {
			t.Errorf("unexpected lvm call: %+v", call)
		}
	}
}

func TestProbeLvmReportsStatfsFailure(t *testing.T) {
	mockLvm(t, map[string]string{"lvs": testLvsOutput, "vgs": testVgsOutput}, nil)
	baseDir := t.TempDir()
	// the mount point does not exist below baseDir
	writeTestFile(t, baseDir, "/proc/self/mounts", "/dev/rootvg/home /gone ext4 rw 0 0\n")

	lvm := probeLvm(baseDir, testTimeouts())

	if lvm == nil || len(lvm.LogicalVolumes) < 3 {
		t.Fatalf("unexpected lvm result: %+v", lvm)
	}
	home := lvm.LogicalVolumes[2]
	if !strings.HasPrefix(home.Error, "statfs /gone: ") || strings.Count(home.Error, "statfs") != 1 || home.FsTotalBytes != nil || home.FsTotalInodes != nil {
		t.Errorf("expected a single statfs error without usage, got %+v", home)
	}
}

func TestProbeLvmWithoutTools(t *testing.T) {
	withoutLvmTools(t)

	if lvm := probeLvm(t.TempDir(), testTimeouts()); lvm != nil {
		t.Errorf("expected no lvm section, got %+v", lvm)
	}
}

func TestProbeLvmFindsToolsInSbin(t *testing.T) {
	mockLvm(t, map[string]string{"lvs": `{"report":[{"lv":[]}]}`, "vgs": `{"report":[{"vg":[]}]}`}, nil)
	lookPath = func(file string) (string, error) {
		if file == "/sbin/lvs" || file == "/sbin/vgs" {
			return file, nil
		}
		return "", errors.New("not found")
	}

	lvm := probeLvm(t.TempDir(), testTimeouts())

	if lvm == nil || lvm.Error != "" || lvm.LogicalVolumes != nil {
		t.Errorf("expected an empty lvm section, got %+v", lvm)
	}
}

func TestProbeLvmReportsCommandErrors(t *testing.T) {
	mockLvm(t, map[string]string{"vgs": testVgsOutput}, map[string]error{"lvs": errors.New("timed out after 5s")})

	lvm := probeLvm(t.TempDir(), testTimeouts())

	if lvm == nil || len(lvm.VolumeGroups) != 1 || lvm.LogicalVolumes != nil {
		t.Fatalf("expected the volume groups only, got %+v", lvm)
	}
	if !strings.HasPrefix(lvm.Error, "lvs: ") || !strings.Contains(lvm.Error, "timed out after 5s") {
		t.Errorf("unexpected error: %q", lvm.Error)
	}
}

func TestProbeLvmRejectsUnexpectedOutput(t *testing.T) {
	mockLvm(t, map[string]string{"lvs": "  WARNING: something", "vgs": testVgsOutput}, nil)

	lvm := probeLvm(t.TempDir(), testTimeouts())

	if lvm == nil || lvm.Error != "lvs: unexpected output: WARNING: something" {
		t.Errorf("unexpected lvm result: %+v", lvm)
	}
}

func TestDeviceMapperName(t *testing.T) {
	cases := map[[2]string]string{
		{"rootvg", "root"}:   "rootvg-root",
		{"my-vg", "var-log"}: "my--vg-var--log",
	}
	for input, expected := range cases {
		if actual := deviceMapperName(input[0], input[1]); actual != expected {
			t.Errorf("deviceMapperName(%q, %q) = %q, expected %q", input[0], input[1], actual, expected)
		}
	}
}

func TestProbeMaster(t *testing.T) {
	baseDir := t.TempDir()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkixDer, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	pkix := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkixDer}))
	pkcs1 := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)}))
	writeTestFile(t, baseDir, MinionKey, string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})))
	writeTestFile(t, baseDir, "/etc/salt/pki/master/minions/node1.example.com", pkix)
	writeTestFile(t, baseDir, "/etc/salt/pki/master/minions/node2.example.com", pkcs1)
	writeTestFile(t, baseDir, "/etc/salt/pki/master/minions/node5.example.com", "garbage")
	writeTestFile(t, baseDir, "/etc/salt/pki/master/minions/.hidden", pkix)
	writeTestFile(t, baseDir, "/etc/salt/pki/master/minions_pre/node3.example.com", pkix)
	writeTestFile(t, baseDir, "/etc/salt/pki/master/minions_rejected/node4.example.com", pkix)
	writeTestFile(t, baseDir, "/etc/salt/pki/master/minions_denied/node1.example.com", pkix)
	if err := os.MkdirAll(baseDir+"/etc/salt/pki/master/minions/subdir", 0755); err != nil {
		t.Fatal(err)
	}

	master := probeMaster(baseDir)

	if master == nil || master.Error != "" {
		t.Fatalf("unexpected master result: %+v", master)
	}
	var states []string
	for _, m := range master.Minions {
		states = append(states, m.Id+"="+m.KeyState)
	}
	expected := "node1.example.com=accepted,node1.example.com=denied,node2.example.com=accepted,node3.example.com=pending,node4.example.com=rejected,node5.example.com=accepted"
	if strings.Join(states, ",") != expected {
		t.Fatalf("unexpected minions: %s", strings.Join(states, ","))
	}
	minionFingerprint := probeMinion(baseDir).Fingerprint
	if minionFingerprint == "" || master.Minions[0].Fingerprint != minionFingerprint || master.Minions[2].Fingerprint != minionFingerprint {
		t.Errorf("expected the accepted keys to match the minion fingerprint %q, got %+v", minionFingerprint, master.Minions)
	}
	if master.Minions[1].Fingerprint != "" || master.Minions[3].Fingerprint != "" {
		t.Errorf("expected fingerprints for accepted keys only, got %+v", master.Minions)
	}
	if master.Minions[5].Error != "fingerprint: cannot decode public key" {
		t.Errorf("expected an error for the broken key, got %+v", master.Minions[5])
	}
}

func TestProbeMasterWithoutMaster(t *testing.T) {
	if master := probeMaster(t.TempDir()); master != nil {
		t.Errorf("expected no master section, got %+v", master)
	}
}

func TestProbeMasterWithoutKeys(t *testing.T) {
	baseDir := t.TempDir()
	if err := os.MkdirAll(baseDir+"/etc/salt/pki/master", 0755); err != nil {
		t.Fatal(err)
	}

	master := probeMaster(baseDir)

	if master == nil || master.Minions == nil || len(master.Minions) != 0 || master.Error != "" {
		t.Errorf("expected an empty minion list, got %+v", master)
	}
}

func writeTestProcess(t *testing.T, baseDir string, pid int, state string, fds int) {
	t.Helper()
	dir := "/proc/" + strconv.Itoa(pid)
	writeTestFile(t, baseDir, dir+"/status", "Name:\tsalt-minion\nState:\t"+state+"\nVmRSS:\t  184320 kB\nThreads:\t12\n")
	// a command name with a space and a ')' must not shift the fields; starttime (field 22) is 50000 ticks = 500s
	writeTestFile(t, baseDir, dir+"/stat", strconv.Itoa(pid)+" (salt minion) x) S 1 1 1 0 -1 4194560 100 0 0 0 10 5 0 0 20 0 12 0 50000 123456 789 18446744073709551615\n")
	for i := 0; i < fds; i++ {
		writeTestFile(t, baseDir, dir+"/fd/"+strconv.Itoa(i), "")
	}
}

func TestProbeUnitsAddsMainProcessStats(t *testing.T) {
	mockCommands(t, map[string]string{
		"/bin/systemctl show salt-bootstrap": "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=0\n",
		"/bin/systemctl show salt-minion":    "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=1234\n",
		"/bin/systemctl show salt-master":    "LoadState=not-found\n",
		"/bin/systemctl show salt-api":       "LoadState=loaded\nActiveState=failed\nSubState=failed\nMainPID=0\n",
	})
	baseDir := t.TempDir()
	writeTestProcess(t, baseDir, 1234, "D (disk sleep)", 3)
	writeTestFile(t, baseDir, "/proc/uptime", "5900.42 11000.00\n")

	units := probeUnits(baseDir, nil, testTimeouts())

	if unitNames(units) != "salt-api,salt-bootstrap,salt-minion" {
		t.Fatalf("unexpected units: %+v", units)
	}
	if units[0].Process != nil {
		t.Errorf("expected no process for a unit without a main PID, got %+v", units[0].Process)
	}
	process := units[2].Process
	if process == nil || process.Error != "" {
		t.Fatalf("unexpected process: %+v", process)
	}
	if process.State != "D (disk sleep)" || *process.RssKb != 184320 || *process.Threads != 12 || *process.OpenFds != 3 || *process.UptimeSeconds != 5400 {
		t.Errorf("unexpected process stats: state %q rss %d threads %d fds %d uptime %d",
			process.State, *process.RssKb, *process.Threads, *process.OpenFds, *process.UptimeSeconds)
	}
}

func TestProbeProcessThatIsGone(t *testing.T) {
	process := probeProcess(t.TempDir(), 4321)

	if process.State != "" || process.RssKb != nil || process.OpenFds != nil || process.UptimeSeconds != nil {
		t.Errorf("expected no stats, got %+v", process)
	}
	for _, part := range []string{"status: ", "fd: ", "uptime: "} {
		if !strings.Contains(process.Error, part) {
			t.Errorf("expected a %q error, got %q", part, process.Error)
		}
	}
}

func mockTool(t *testing.T, name string) {
	t.Helper()
	originalLookPath := lookPath
	t.Cleanup(func() { lookPath = originalLookPath })
	lookPath = func(file string) (string, error) {
		if file == name {
			return "/usr/sbin/" + name, nil
		}
		return "", errors.New("not found")
	}
}

func withClock(t *testing.T, now time.Time) {
	t.Helper()
	original := diagnosticsNow
	t.Cleanup(func() { diagnosticsNow = original })
	diagnosticsNow = func() time.Time { return now }
}

func intPtr(i int) *int { return &i }

func TestDiagnosticsRequestProbeDeadline(t *testing.T) {
	cases := []struct {
		deadline string
		expected time.Duration
		error    string
	}{
		{"", diagConfig().ProbeDeadline, ""},
		{"15s", 15 * time.Second, ""},
		{"500ms", 500 * time.Millisecond, ""},
		{"15", 0, `invalid probeDeadline "15": time: missing unit in duration "15"`},
		{"soon", 0, `invalid probeDeadline "soon"`},
		{"0s", 0, "probeDeadline must be positive, got 0s"},
		{"-1s", 0, "probeDeadline must be positive, got -1s"},
	}
	for _, c := range cases {
		request := DiagnosticsRequest{ProbeDeadline: c.deadline}
		deadline, err := request.probeDeadline()
		if c.error == "" && (err != nil || deadline != c.expected) {
			t.Errorf("%q: expected %s, got %s, %v", c.deadline, c.expected, deadline, err)
		} else if c.error != "" && (err == nil || !strings.Contains(err.Error(), c.error) || request.validate() == nil) {
			t.Errorf("%q: expected an error containing %q, got %v", c.deadline, c.error, err)
		}
	}
}

func TestSelectAdditionalUnits(t *testing.T) {
	limit := diagConfig().MaxAdditionalUnits
	many := make([]string, limit+2)
	for i := range many {
		many[i] = "unit" + strconv.Itoa(i)
	}
	invalid := "not a plain systemd unit name of at most 255 characters"
	cases := []struct {
		name     string
		units    []string
		probed   string
		rejected string
	}{
		{"no units", nil, "", ""},
		{"plain names", []string{"nginx", "a-proxy.service", "user@1000.service", "dev-sda1.device", "a:b_c"},
			"nginx,a-proxy,user@1000,dev-sda1.device,a:b_c", ""},
		{"service suffix is dropped", []string{"salt-minion.service"}, "salt-minion", ""},
		{"service suffix does not count against the limit", append([]string{"salt-minion.service"}, many[:limit]...),
			"salt-minion," + strings.Join(many[:limit], ","), ""},
		{"same unit with and without the suffix", []string{"foo", "foo.service", "foo"}, "foo", ""},
		{"only the service suffix is dropped", []string{"foo.socket", "foo.timer"}, "foo.socket,foo.timer", ""},
		{"exactly the maximum", many[:limit], strings.Join(many[:limit], ","), ""},
		{"over the maximum in request order", many, strings.Join(many[:limit], ","),
			fmt.Sprintf("unit%d: more than %d additional units requested|unit%d: more than %d additional units requested", limit, limit, limit+1, limit)},
		{"salt units count against no limit", append([]string{"salt-master"}, many[:limit]...), "salt-master," + strings.Join(many[:limit], ","), ""},
		{"duplicates count once", []string{"nginx", "nginx", "nginx"}, "nginx", ""},
		{"leading dash", []string{"--all", "nginx"}, "nginx", "--all: " + invalid},
		{"glob star", []string{"salt-*"}, "", "salt-*: " + invalid},
		{"glob question mark", []string{"ngin?"}, "", "ngin?: " + invalid},
		{"empty", []string{""}, "", ": " + invalid},
		{"space", []string{"nginx service"}, "", "nginx service: " + invalid},
		{"slash", []string{"../etc/passwd"}, "", "../etc/passwd: " + invalid},
		{"too long", []string{strings.Repeat("a", 300)}, "", strings.Repeat("a", 300) + ": " + invalid},
	}
	for _, c := range cases {
		probed, rejected := DiagnosticsRequest{AdditionalUnits: c.units}.selectAdditionalUnits()
		var rejections []string
		for _, unit := range rejected {
			rejections = append(rejections, unit.Name+": "+unit.Rejected)
		}
		if strings.Join(probed, ",") != c.probed {
			t.Errorf("%s: expected %q to be probed, got %q", c.name, c.probed, strings.Join(probed, ","))
		}
		if got := strings.Join(rejections, "|"); !strings.HasPrefix(got, c.rejected) || (c.rejected == "") != (got == "") {
			t.Errorf("%s: expected the rejections %q, got %q", c.name, c.rejected, got)
		}
	}
}

func TestDiagnosticsHandlerReportsRejectedUnitsWithoutProbingThem(t *testing.T) {
	// a rejected unit must never reach systemctl, which the mock would report as an unexpected command
	mockCommands(t, map[string]string{
		"/bin/systemctl show salt-": "LoadState=loaded\nActiveState=active\n",
		"/bin/systemctl show nginx": "LoadState=loaded\nActiveState=active\n",
		"timedatectl show":          "NTP=yes\n",
	})

	req := httptest.NewRequest("POST", "/saltboot/diagnostics", bytes.NewBufferString(`{"logLines": 0, "additionalUnits": ["-p", "nginx", "salt-*"]}`))
	req.Header.Set("salt-minion-base-dir", t.TempDir())
	w := httptest.NewRecorder()
	DiagnosticsHandler(w, req)

	var node NodeDiagnostics
	if err := json.Unmarshal(w.Body.Bytes(), &node); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected the request to run, got %d %+v", w.Code, node)
	}
	byName := map[string]UnitDiagnostics{}
	for _, unit := range node.Units {
		byName[unit.Name] = unit
	}
	for _, name := range []string{"-p", "salt-*"} {
		if unit := byName[name]; !strings.HasPrefix(unit.Rejected, "not a plain systemd unit name") || unit.Error != "" || unit.LoadState != "" {
			t.Errorf("expected %s to be rejected without being probed, got %+v", name, unit)
		}
	}
	if nginx := byName["nginx"]; nginx.ActiveState != "active" || nginx.Rejected != "" {
		t.Errorf("expected nginx to be probed, got %+v", nginx)
	}
}

func TestDiagnosticsDistributeHandlerRejectsAnInvalidProbeDeadline(t *testing.T) {
	bodies := map[string]string{
		"invalid":                      `{"targets": ["10.0.0.1"], "probeDeadline": "soon"}`,
		"equal to the fan-out timeout": `{"targets": ["10.0.0.1"], "probeDeadline": "20s"}`,
		"over the fan-out timeout":     `{"targets": ["10.0.0.1"], "probeDeadline": "1m"}`,
		"within the response margin":   `{"targets": ["10.0.0.1"], "probeDeadline": "19.5s"}`,
	}
	expected := map[string]string{
		"invalid":                      `invalid probeDeadline "soon"`,
		"equal to the fan-out timeout": "probeDeadline 20s leaves less than 1s of the distributeTimeout 20s of this node for the response",
		"over the fan-out timeout":     "probeDeadline 1m0s leaves less than 1s of the distributeTimeout 20s of this node for the response",
		"within the response margin":   "probeDeadline 19.5s leaves less than 1s of the distributeTimeout 20s of this node for the response",
	}
	for name, body := range bodies {
		req := httptest.NewRequest("POST", "/saltboot/diagnostics/distribute", bytes.NewBufferString(body))
		w := httptest.NewRecorder()
		DiagnosticsDistributeHandler(w, req)

		var response DiagnosticsResponse
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if w.Code != http.StatusBadRequest || !strings.Contains(response.ErrorText, expected[name]) || response.Nodes != nil {
			t.Errorf("%s: expected a 400 with %q before any fan-out, got %d %+v", name, expected[name], w.Code, response)
		}
	}
}

func TestCollectDiagnosticsUsesTheRequestedProbeDeadline(t *testing.T) {
	withoutLvmTools(t)
	release, finished := make(chan struct{}), make(chan struct{})
	originalExec, originalTimedExec, originalStat := commandExecutor, timedCommandExecutor, stat
	// the abandoned probe still runs, so let it finish before restoring the globals it reads
	defer func() {
		close(release)
		<-finished
		commandExecutor, timedCommandExecutor, stat = originalExec, originalTimedExec, originalStat
	}()
	stat = initOk
	commandExecutor = func(executable string, args ...string) ([]byte, error) {
		return nil, errors.New("not available")
	}
	timedCommandExecutor = func(timeout time.Duration, executable string, args ...string) ([]byte, error) {
		switch executable {
		case "timedatectl":
			<-release
			defer close(finished)
		case SYSTEM_D.StateBin:
		default:
			return nil, errors.New("not available")
		}
		return []byte("LoadState=loaded\nActiveState=active\n"), nil
	}

	// the configured deadline is 10s, the request asks for less
	start := time.Now()
	diagnostics := collectDiagnostics(t.TempDir(), DiagnosticsRequest{ProbeDeadline: "150ms", LogLines: intPtr(0)})

	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("the requested deadline was not applied, collecting took %s", elapsed)
	}
	if diagnostics.ProbeDeadline != "150ms" || !slices.Contains(diagnostics.TimedOutProbes, "time") {
		t.Errorf("expected the requested deadline and the time probe timed out, got %s %v", diagnostics.ProbeDeadline, diagnostics.TimedOutProbes)
	}
	if diagnostics.ConfigFingerprint != diagConfig().fingerprint() || diagnostics.ConfigFingerprint == "" {
		t.Errorf("expected the node's config fingerprint, got %q", diagnostics.ConfigFingerprint)
	}
}

func TestProbeUnitsReportsRequestedUnits(t *testing.T) {
	mockCommands(t, map[string]string{
		"/bin/systemctl show salt-bootstrap": "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=0\n",
		"/bin/systemctl show salt-minion":    "LoadState=loaded\nActiveState=active\nSubState=running\n",
		"/bin/systemctl show salt-master":    "LoadState=not-found\n",
		"/bin/systemctl show salt-api":       "LoadState=not-found\n",
		"/bin/systemctl show nginx":          "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=0\n",
		"/bin/systemctl show a-proxy":        "LoadState=not-found\nActiveState=inactive\nSubState=dead\n",
	})

	// salt-minion is a built-in and nginx is requested twice, so both are probed once
	units := probeUnits(t.TempDir(), []string{"nginx", "salt-minion", "a-proxy", "nginx"}, testTimeouts())

	if unitNames(units) != "a-proxy,nginx,salt-bootstrap,salt-minion" {
		t.Fatalf("unexpected units: %+v", units)
	}
	if units[0].LoadState != "not-found" || units[0].Error != "" {
		t.Errorf("expected the missing requested unit to be reported as not found, got %+v", units[0])
	}
	if units[1].ActiveState != "active" {
		t.Errorf("unexpected nginx state: %+v", units[1])
	}

	// asking for an optional built-in makes it required as well
	units = probeUnits(t.TempDir(), []string{"salt-master"}, testTimeouts())
	if unitNames(units) != "salt-bootstrap,salt-master,salt-minion" || units[1].LoadState != "not-found" {
		t.Errorf("expected the requested salt-master, got %+v", units)
	}
}

func TestProbeUnitsProbesTheUnitsConcurrently(t *testing.T) {
	mockCommands(t, map[string]string{
		"/bin/systemctl show":             "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=0\n",
		"/bin/systemctl show salt-master": "LoadState=not-found\n",
		"/bin/systemctl show salt-api":    "LoadState=not-found\n",
	})
	fast := timedCommandExecutor
	timedCommandExecutor = func(timeout time.Duration, executable string, args ...string) ([]byte, error) {
		time.Sleep(200 * time.Millisecond)
		return fast(timeout, executable, args...)
	}

	start := time.Now()
	units := probeUnits(t.TempDir(), []string{"zeta", "alpha", "nginx"}, testTimeouts())
	elapsed := time.Since(start)

	// seven units are probed, optional salt-master and salt-api among them; one after another they would take 1.4s
	if unitNames(units) != "alpha,nginx,salt-bootstrap,salt-minion,zeta" {
		t.Errorf("expected the units sorted by name, got %+v", units)
	}
	if elapsed > 800*time.Millisecond {
		t.Errorf("expected the units to be probed concurrently, took %s", elapsed)
	}
}

func TestProbeUnitsReportsRequestedUnitErrors(t *testing.T) {
	mockCommands(t, map[string]string{
		"/bin/systemctl show salt-bootstrap": "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=0\n",
		"/bin/systemctl show salt-minion":    "LoadState=loaded\n",
		"/bin/systemctl show salt-master":    "LoadState=not-found\n",
		"/bin/systemctl show salt-api":       "LoadState=not-found\n",
	}, "/bin/systemctl show broken")

	units := probeUnits(t.TempDir(), []string{"broken"}, testTimeouts())

	if unitNames(units) != "broken,salt-bootstrap,salt-minion" || units[0].Error == "" {
		t.Errorf("expected an error for the broken unit, got %+v", units)
	}
}

func TestDiagnosticsHandlerProbesRequestedUnits(t *testing.T) {
	mockCommands(t, map[string]string{
		"/bin/systemctl show":             "LoadState=not-found\n",
		"/bin/systemctl show salt-minion": "LoadState=loaded\nActiveState=active\n",
		"timedatectl show":                "NTP=yes\n",
	})

	req := httptest.NewRequest("POST", "/saltboot/diagnostics", bytes.NewBufferString(`{"logLines": 0, "additionalUnits": ["my-unit@1.service"]}`))
	req.Header.Set("salt-minion-base-dir", t.TempDir())
	w := httptest.NewRecorder()
	DiagnosticsHandler(w, req)

	var diagnostics NodeDiagnostics
	if err := json.Unmarshal(w.Body.Bytes(), &diagnostics); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK || unitNames(diagnostics.Units) != "my-unit@1,salt-bootstrap,salt-minion" {
		t.Errorf("unexpected units: %d %+v", w.Code, diagnostics.Units)
	}
}

func TestParseShadowEntry(t *testing.T) {
	// 2026-11-18 is day 20775
	now := time.Date(2026, 11, 18, 15, 30, 0, 0, time.UTC)
	cases := []struct {
		name     string
		entry    string
		expected SaltUserDiagnostics
	}{
		{"healthy", "saltuser:$6$salt$HASH:20765:0:90:7:::", SaltUserDiagnostics{
			Present: true, LastChange: "2026-11-08", MinDays: intPtr(0), MaxDays: intPtr(90), WarnDays: intPtr(7),
			PasswordExpiresAt: "2027-02-06", DaysUntilPasswordExpiry: intPtr(80)}},
		{"expired with inactivity period", "saltuser:$6$salt$HASH:20700:0:30:7:14::", SaltUserDiagnostics{
			Present: true, LastChange: "2026-09-04", MinDays: intPtr(0), MaxDays: intPtr(30), WarnDays: intPtr(7), InactiveDays: intPtr(14),
			PasswordExpiresAt: "2026-10-04", PasswordExpired: true, DaysUntilPasswordExpiry: intPtr(-45), PasswordInactiveAt: "2026-10-18"}},
		{"expires today is not yet expired", "saltuser:$6$salt$HASH:20745::30::::", SaltUserDiagnostics{
			Present: true, LastChange: "2026-10-19", MaxDays: intPtr(30), PasswordExpiresAt: "2026-11-18", DaysUntilPasswordExpiry: intPtr(0)}},
		{"never expires", "saltuser:$6$salt$HASH:20700:0:99999:7:::", SaltUserDiagnostics{
			Present: true, LastChange: "2026-09-04", MinDays: intPtr(0), MaxDays: intPtr(99999), WarnDays: intPtr(7)}},
		{"no max days", "saltuser:$6$salt$HASH:20700::::::", SaltUserDiagnostics{Present: true, LastChange: "2026-09-04"}},
		{"change required", "saltuser:$6$salt$HASH:0:0:90:7:::", SaltUserDiagnostics{
			Present: true, PasswordChangeRequired: true, MinDays: intPtr(0), MaxDays: intPtr(90), WarnDays: intPtr(7)}},
		{"locked", "saltuser:!$6$salt$HASH:20765::::::", SaltUserDiagnostics{Present: true, Locked: true, LastChange: "2026-11-08"}},
		{"locked with star", "saltuser:*:20765::::::", SaltUserDiagnostics{Present: true, Locked: true, LastChange: "2026-11-08"}},
		{"locked with double bang", "saltuser:!!:20765::::::", SaltUserDiagnostics{Present: true, Locked: true, LastChange: "2026-11-08"}},
		{"empty password", "saltuser::20765::::::", SaltUserDiagnostics{Present: true, EmptyPassword: true, LastChange: "2026-11-08"}},
		{"account expired", "saltuser:$6$salt$HASH:20765:::::20775:", SaltUserDiagnostics{
			Present: true, LastChange: "2026-11-08", AccountExpiresAt: "2026-11-18", AccountExpired: true}},
		{"account expires tomorrow", "saltuser:$6$salt$HASH:20765:::::20776:", SaltUserDiagnostics{
			Present: true, LastChange: "2026-11-08", AccountExpiresAt: "2026-11-19"}},
		{"account never expires", "saltuser:$6$salt$HASH:20765:::::-1:", SaltUserDiagnostics{Present: true, LastChange: "2026-11-08"}},
		{"short line", "saltuser:$6$salt$HASH", SaltUserDiagnostics{Present: true}},
	}
	for _, c := range cases {
		var actual SaltUserDiagnostics
		parseShadowEntry(c.entry, now, &actual)

		actualJson, _ := json.Marshal(actual)
		expectedJson, _ := json.Marshal(c.expected)
		if string(actualJson) != string(expectedJson) {
			t.Errorf("%s:\n got %s\nwant %s", c.name, actualJson, expectedJson)
		}
	}
}

func TestProbeSaltUser(t *testing.T) {
	withClock(t, time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC))
	withoutLvmTools(t)
	baseDir := t.TempDir()
	writeTestFile(t, baseDir, "/etc/shadow", "root:$6$rootsalt$ROOTHASH:19000::::::\nsaltuser:$6$SECRETSALT$SECRETHASH/abc:20700:0:30:7:14::\n")
	writeTestFile(t, baseDir, "/etc/passwd", "root:x:0:0::/root:/bin/bash\nsaltuser:x:1001:1001::/:/sbin/nologin\n")
	writeTestFile(t, baseDir, "/etc/group", "root:x:0:\n")
	if err := os.Chmod(baseDir+"/etc/shadow", 0640); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, baseDir, SHADOW_FILE_NEW, "saltuser:$6$new$NEWHASH:20775::::::\n")

	saltUser := probeSaltUser(baseDir, testTimeouts(), "")

	if saltUser == nil || saltUser.Error != "" {
		t.Fatalf("unexpected saltUser: %+v", saltUser)
	}
	if !saltUser.Present || !saltUser.PasswordExpired || !saltUser.PasswdEntry || !saltUser.ShadowNewLeftover || saltUser.FaillockFailures != nil {
		t.Errorf("unexpected saltUser: %+v", saltUser)
	}
	if len(saltUser.Files) != 3 || saltUser.Files[0].Path != "/etc/passwd" || saltUser.Files[1].Path != "/etc/shadow" || saltUser.Files[2].Path != "/etc/group" {
		t.Fatalf("unexpected files: %+v", saltUser.Files)
	}
	shadow := saltUser.Files[1]
	if shadow.Mode != "0640" || shadow.Uid == nil || *shadow.Uid != os.Getuid() || shadow.Gid == nil || *shadow.Gid != os.Getgid() || shadow.Error != "" {
		t.Errorf("unexpected shadow file: %+v", shadow)
	}

	b, _ := json.Marshal(saltUser)
	for _, secret := range []string{"SECRETHASH", "SECRETSALT", "$6$", "ROOTHASH", "NEWHASH"} {
		if strings.Contains(string(b), secret) {
			t.Errorf("the response must not contain %q: %s", secret, b)
		}
	}
}

func TestProbeSaltUserPresence(t *testing.T) {
	cases := []struct {
		name    string
		files   map[string]string
		omitted bool
		present bool
		error   string
	}{
		{"no shadow, not a master", nil, true, false, ""},
		{"shadow without saltuser, not a master", map[string]string{"/etc/shadow": "root:!:19000::::::\n"}, true, false, ""},
		{"saltuser prefix of another account", map[string]string{"/etc/shadow": "saltuser2:!:19000::::::\n"}, true, false, ""},
		{"shadow with saltuser", map[string]string{"/etc/shadow": "saltuser:!:19000::::::\n"}, false, true, ""},
		{"master without saltuser", map[string]string{"/etc/shadow": "root:!:19000::::::\n", "/etc/salt/pki/master/master.pub": "x"}, false, false, ""},
		{"master without shadow", map[string]string{"/etc/salt/pki/master/master.pub": "x"}, false, false, "shadow: "},
	}
	withoutLvmTools(t)
	for _, c := range cases {
		baseDir := t.TempDir()
		for path, content := range c.files {
			writeTestFile(t, baseDir, path, content)
		}

		saltUser := probeSaltUser(baseDir, testTimeouts(), "")

		if c.omitted {
			if saltUser != nil {
				t.Errorf("%s: expected no saltUser section, got %+v", c.name, saltUser)
			}
			continue
		}
		if saltUser == nil {
			t.Errorf("%s: expected a saltUser section", c.name)
			continue
		}
		if saltUser.Present != c.present || !strings.HasPrefix(saltUser.Error, c.error) || (c.error == "" && saltUser.Error != "") || saltUser.PasswdEntry || saltUser.ShadowNewLeftover {
			t.Errorf("%s: unexpected saltUser: %+v", c.name, saltUser)
		}
	}
}

func TestProbeSaltUserFaillock(t *testing.T) {
	baseDir := t.TempDir()
	writeTestFile(t, baseDir, "/etc/shadow", "saltuser:$6$s$h:20700::::::\n")
	output := strings.Join([]string{
		"saltuser:",
		"When                Type  Source                                           Valid",
		"2026-11-18 10:00:00 RHOST 10.0.0.1                                             V",
		"2026-11-18 10:00:05 RHOST 10.0.0.1                                             V",
		"2026-11-17 10:00:09 TTY   /dev/pts/0                                           I",
	}, "\n")

	mockCommands(t, map[string]string{"/usr/sbin/faillock --user saltuser": output})
	mockTool(t, "faillock")
	saltUser := probeSaltUser(baseDir, testTimeouts(), "")
	if saltUser == nil || saltUser.Error != "" || saltUser.FaillockFailures == nil || *saltUser.FaillockFailures != 2 {
		t.Errorf("expected 2 valid failures, got %+v", saltUser)
	}

	mockCommands(t, map[string]string{"/usr/sbin/faillock --user saltuser": "saltuser:\nWhen Type Source Valid\n"})
	mockTool(t, "faillock")
	if saltUser = probeSaltUser(baseDir, testTimeouts(), ""); saltUser.FaillockFailures == nil || *saltUser.FaillockFailures != 0 {
		t.Errorf("expected 0 failures, got %+v", saltUser)
	}

	mockCommands(t, nil, "/usr/sbin/faillock")
	mockTool(t, "faillock")
	if saltUser = probeSaltUser(baseDir, testTimeouts(), ""); saltUser.FaillockFailures != nil || !strings.HasPrefix(saltUser.Error, "faillock: ") {
		t.Errorf("expected an faillock error and no count, got %+v", saltUser)
	}

	mockCommands(t, nil)
	if saltUser = probeSaltUser(baseDir, testTimeouts(), ""); saltUser.FaillockFailures != nil || saltUser.Error != "" {
		t.Errorf("expected no faillock result without the tool, got %+v", saltUser)
	}
}

func TestProbeSaltUserFilesMissing(t *testing.T) {
	baseDir := t.TempDir()
	writeTestFile(t, baseDir, "/etc/shadow", "saltuser:!:20700::::::\n")
	withoutLvmTools(t)

	saltUser := probeSaltUser(baseDir, testTimeouts(), "")

	if saltUser == nil || saltUser.PasswdEntry || len(saltUser.Files) != 3 {
		t.Fatalf("unexpected saltUser: %+v", saltUser)
	}
	if passwd := saltUser.Files[0]; passwd.Error == "" || passwd.Mode != "" || passwd.Uid != nil {
		t.Errorf("expected an error for the missing /etc/passwd, got %+v", passwd)
	}
}

type testKeys struct{ pkix, pkcs1, fingerprint string }

func newTestKeys(t *testing.T) testKeys {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkixDer, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	keys := testKeys{
		pkix:  string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkixDer})),
		pkcs1: string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)})),
	}
	if keys.fingerprint, err = getFingerprintOfPublicKeyPem([]byte(keys.pkix)); err != nil {
		t.Fatal(err)
	}
	return keys
}

func TestProbeKeyFingerprintsAreComparableBetweenMinionAndMaster(t *testing.T) {
	masterKey, signKey := newTestKeys(t), newTestKeys(t)
	minionDir, masterDir := t.TempDir(), t.TempDir()
	writeTestFile(t, minionDir, "/etc/salt/pki/minion/minion_master.pub", masterKey.pkix)
	writeTestFile(t, minionDir, "/etc/salt/pki/minion/master_sign.pub", signKey.pkcs1)
	writeTestFile(t, masterDir, "/etc/salt/pki/master/master.pub", masterKey.pkcs1)
	writeTestFile(t, masterDir, "/etc/salt/pki/master/master_sign.pub", signKey.pkix)

	minion, master := probeMinion(minionDir), probeMaster(masterDir)

	if minion.MasterKeyFingerprint != masterKey.fingerprint || minion.MasterSignKeyFingerprint != signKey.fingerprint {
		t.Errorf("unexpected minion fingerprints: %+v", minion)
	}
	if master.KeyFingerprint != masterKey.fingerprint || master.SignKeyFingerprint != signKey.fingerprint || master.Error != "" {
		t.Errorf("unexpected master fingerprints: %+v", master)
	}
	if strings.Contains(minion.Error, "minion_master.pub") || strings.Contains(minion.Error, "master_sign.pub") {
		t.Errorf("unexpected key errors: %q", minion.Error)
	}
}

func TestProbeMinionKeyErrors(t *testing.T) {
	cases := []struct {
		name     string
		files    map[string]string
		expected string
	}{
		{"missing master key", nil, "minion_master.pub: missing"},
		{"broken master key", map[string]string{"minion_master.pub": "garbage"}, "minion_master.pub: cannot decode public key"},
		{"broken sign key", map[string]string{"minion_master.pub": "garbage", "master_sign.pub": "garbage"}, "master_sign.pub: cannot decode public key"},
	}
	for _, c := range cases {
		baseDir := t.TempDir()
		for name, content := range c.files {
			writeTestFile(t, baseDir, "/etc/salt/pki/minion/"+name, content)
		}

		minion := probeMinion(baseDir)

		if !strings.Contains(minion.Error, c.expected) || minion.MasterKeyFingerprint != "" || minion.MasterSignKeyFingerprint != "" {
			t.Errorf("%s: expected %q in the error, got %+v", c.name, c.expected, minion)
		}
	}

	// the sign key is optional, so a missing one is no error
	baseDir := t.TempDir()
	writeTestFile(t, baseDir, "/etc/salt/pki/minion/minion_master.pub", newTestKeys(t).pkix)
	if minion := probeMinion(baseDir); strings.Contains(minion.Error, "master_sign.pub") || minion.MasterKeyFingerprint == "" || minion.MasterSignKeyFingerprint != "" {
		t.Errorf("unexpected minion: %+v", minion)
	}
}

func TestProbeMasterKeyErrors(t *testing.T) {
	baseDir := t.TempDir()
	writeTestFile(t, baseDir, "/etc/salt/pki/master/master.pub", "garbage")

	master := probeMaster(baseDir)

	if master == nil || master.KeyFingerprint != "" || master.Error != "master.pub: cannot decode public key" {
		t.Errorf("unexpected master: %+v", master)
	}
}

func hostCommands() map[string]string {
	return map[string]string{"hostname -s": "node1", "hostname -f": "node1.example.com"}
}

func mockHostLookup(t *testing.T, lookup func(ctx context.Context, host string) ([]string, error), addrs []net.Addr) {
	t.Helper()
	originalLookup, originalAddrs := lookupHost, interfaceAddrs
	t.Cleanup(func() { lookupHost, interfaceAddrs = originalLookup, originalAddrs })
	lookupHost = lookup
	interfaceAddrs = func() ([]net.Addr, error) { return addrs, nil }
}

func TestProbeHost(t *testing.T) {
	mockCommands(t, hostCommands())
	mockHostLookup(t, func(ctx context.Context, host string) ([]string, error) {
		if _, ok := ctx.Deadline(); !ok || host != "node1.example.com" {
			t.Errorf("expected a lookup of the FQDN with a deadline, got %s %v", host, ctx)
		}
		return []string{"10.0.0.5"}, nil
	}, []net.Addr{
		&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
		&net.IPNet{IP: net.ParseIP("10.0.0.5"), Mask: net.CIDRMask(24, 32)},
		&net.IPNet{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)},
		&net.IPAddr{IP: net.ParseIP("fd00::5")},
	})
	baseDir := t.TempDir()
	writeTestFile(t, baseDir, "/etc/hostname", "node1.example.com\n")
	writeTestFile(t, baseDir, "/etc/resolv.conf", "# generated\nnameserver 10.0.0.2\nnameserver 10.0.0.3\nsearch old.example.com\nsearch example.com internal.example.com\noptions edns0\n")
	writeTestFile(t, baseDir, "/etc/hosts", "127.0.0.1 localhost\n  10.0.0.5 node1.example.com node1 # self  \n10.0.0.6 node10.example.com node10\n10.0.0.7 other # node1\n::1 localhost")

	host := probeHost(baseDir, testTimeouts())

	if host.Error != "" || host.Hostname != "node1" || host.Fqdn != "node1.example.com" || host.EtcHostname != "node1.example.com" {
		t.Errorf("unexpected names: %+v", host)
	}
	if strings.Join(host.FqdnAddresses, ",") != "10.0.0.5" || host.FqdnError != "" || strings.Join(host.Addresses, ",") != "10.0.0.5,fd00::5" {
		t.Errorf("unexpected addresses: %+v", host)
	}
	if strings.Join(host.Nameservers, ",") != "10.0.0.2,10.0.0.3" || strings.Join(host.SearchDomains, ",") != "example.com,internal.example.com" {
		t.Errorf("unexpected resolv.conf: %+v", host)
	}
	if strings.Join(host.HostsEntries, "|") != "10.0.0.5 node1.example.com node1 # self" || !host.HostsMissingTrailingNewline {
		t.Errorf("unexpected hosts: %q %v", host.HostsEntries, host.HostsMissingTrailingNewline)
	}
}

func TestProbeHostFallsBackToPlainHostname(t *testing.T) {
	mockCommands(t, map[string]string{"hostname": "node1.example.com", "hostname -f": "node1.example.com"}, "hostname -s")
	mockHostLookup(t, func(ctx context.Context, host string) ([]string, error) { return nil, nil }, nil)

	host := probeHost(t.TempDir(), testTimeouts())

	if host.Hostname != "node1.example.com" || host.Fqdn != "node1.example.com" {
		t.Errorf("unexpected host: %+v", host)
	}
}

func TestProbeHostReportsFailures(t *testing.T) {
	mockCommands(t, nil, "hostname")
	mockHostLookup(t, func(ctx context.Context, host string) ([]string, error) {
		t.Errorf("no lookup is expected without an FQDN")
		return nil, nil
	}, nil)

	host := probeHost(t.TempDir(), testTimeouts())

	// the files are missing as well: only /etc/hostname is allowed to be
	for _, part := range []string{"hostname: ", "fqdn: ", "resolv.conf: ", "hosts: "} {
		if !strings.Contains(host.Error, part) {
			t.Errorf("expected a %q error, got %q", part, host.Error)
		}
	}
	if strings.Contains(host.Error, "hostname file") || host.Hostname != "" || host.Fqdn != "" || host.HostsEntries != nil || host.HostsMissingTrailingNewline {
		t.Errorf("unexpected host: %+v", host)
	}
}

func TestProbeHostReportsFqdnLookupFailure(t *testing.T) {
	mockCommands(t, hostCommands())
	mockHostLookup(t, func(ctx context.Context, host string) ([]string, error) {
		return nil, errors.New("no such host")
	}, nil)

	host := probeHost(t.TempDir(), testTimeouts())

	if host.FqdnError != "no such host" || host.FqdnAddresses != nil {
		t.Errorf("unexpected host: %+v", host)
	}
}

func TestProbeHostGivesUpOnAHangingResolver(t *testing.T) {
	setDiagnosticsConfig(t, func(c *DiagnosticsConfig) { c.LookupTimeout = 50 * time.Millisecond })
	mockCommands(t, hostCommands())
	mockHostLookup(t, func(ctx context.Context, host string) ([]string, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}, nil)

	host := probeHost(t.TempDir(), testTimeouts())

	if host.FqdnError != "context deadline exceeded" || host.Fqdn != "node1.example.com" {
		t.Errorf("unexpected host: %+v", host)
	}
}

func TestCollectDiagnosticsTimesOutOnlyTheHostProbeOnAHangingResolver(t *testing.T) {
	setDiagnosticsConfig(t, func(c *DiagnosticsConfig) { c.ProbeDeadline = 200 * time.Millisecond })
	mockCommands(t, map[string]string{
		"/bin/systemctl show": "LoadState=loaded\n", "timedatectl show": "NTP=yes\n",
		"hostname -s": "node1", "hostname -f": "node1.example.com",
	})
	release, finished := make(chan struct{}), make(chan struct{})
	originalLookup, originalAddrs := lookupHost, interfaceAddrs
	// the abandoned probe still runs, so let it get past the last injected call before restoring them
	defer func() { close(release); <-finished; lookupHost, interfaceAddrs = originalLookup, originalAddrs }()
	lookupHost = func(ctx context.Context, host string) ([]string, error) {
		<-release
		return nil, nil
	}
	interfaceAddrs = func() ([]net.Addr, error) {
		defer close(finished)
		return nil, nil
	}

	diagnostics := collectDiagnostics(t.TempDir(), requestWithLogLines(0))

	if strings.Join(diagnostics.TimedOutProbes, ",") != "host" {
		t.Errorf("expected only the host probe to time out, got %v", diagnostics.TimedOutProbes)
	}
	if diagnostics.Host != nil || diagnostics.Time == nil || len(diagnostics.Units) == 0 || diagnostics.Minion == nil {
		t.Errorf("unexpected diagnostics: %+v", diagnostics)
	}
}

func TestParseResolvConfAndHostsEntries(t *testing.T) {
	nameservers, search := parseResolvConf("")
	if nameservers != nil || search != nil {
		t.Errorf("expected nothing from an empty file, got %v %v", nameservers, search)
	}
	if nameservers, search = parseResolvConf("domain example.com\nnameserver\nnameserver 1.1.1.1\n"); strings.Join(nameservers, ",") != "1.1.1.1" || strings.Join(search, ",") != "example.com" {
		t.Errorf("unexpected resolv.conf: %v %v", nameservers, search)
	}

	if entries := hostsEntriesFor("10.0.0.1 a b\n10.0.0.2 c\n", "", "d"); entries != nil {
		t.Errorf("expected no entries for unknown or empty names, got %v", entries)
	}
	if entries := hostsEntriesFor("10.0.0.1 a b\n10.0.0.2 c\n\n", "c", "b"); strings.Join(entries, "|") != "10.0.0.1 a b|10.0.0.2 c" {
		t.Errorf("unexpected entries: %v", entries)
	}
}

const testExecStart = "ExecStart={ path=%[1]s ; argv[]=%[1]s -d ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }"

func mockExecStart(t *testing.T, minion, master string, extra map[string]string) {
	t.Helper()
	outputs := map[string]string{
		"/bin/systemctl show salt-minion -p ExecStart": fmt.Sprintf(testExecStart, minion),
		"/bin/systemctl show salt-master -p ExecStart": "ExecStart=",
	}
	if master != "" {
		outputs["/bin/systemctl show salt-master -p ExecStart"] = fmt.Sprintf(testExecStart, master)
	}
	for command, out := range extra {
		outputs[command] = out
	}
	mockCommands(t, outputs)
}

func TestProbeSaltVersions(t *testing.T) {
	cases := []struct {
		name          string
		files         map[string]string
		version       string
		pythonVersion string
	}{
		{"_version.txt", map[string]string{
			"/opt/salt_3006.10/bin/salt-minion":                                             "#!/opt/salt_3006.10/bin/python3.10\nimport salt\n",
			"/opt/salt_3006.10/lib/python3.10/site-packages/salt/_version.txt":              "3006.10\n",
			"/opt/salt_3006.10/lib/python3.10/site-packages/salt-3005.1.dist-info/METADATA": "Version: 3005.1\n"},
			"3006.10", "3.10"},
		{"dist-info", map[string]string{
			"/opt/salt_3006.10/bin/salt-minion":                                              "#!/opt/salt_3006.10/bin/python3.10\n",
			"/opt/salt_3006.10/lib/python3.10/site-packages/salt-3006.10.dist-info/METADATA": "Metadata-Version: 2.1\nName: salt\nVersion: 3006.10\nSummary: x\n\nVersion: 1.0 in the description\n"},
			"3006.10", "3.10"},
		{"egg-info directory", map[string]string{
			"/opt/salt_3006.10/bin/salt-minion":                                                    "#!/opt/salt_3006.10/bin/python3.10\n",
			"/opt/salt_3006.10/lib/python3.10/site-packages/salt-3006.10-py3.10.egg-info/PKG-INFO": "Metadata-Version: 1.1\nName: salt\nVersion: 3006.10\n"},
			"3006.10", "3.10"},
		{"egg-info file in lib64", map[string]string{
			"/opt/salt_3006.10/bin/salt-minion":                                           "#!/opt/salt_3006.10/bin/python3.9\n",
			"/opt/salt_3006.10/lib64/python3.9/site-packages/salt-3006.10-py3.9.egg-info": "Metadata-Version: 1.1\nName: salt\nVersion: 3006.10\n"},
			"3006.10", "3.9"},
		{"interpreter prefix differs from the executable", map[string]string{
			"/opt/salt_3006.10/bin/salt-minion":                         "#!/usr/bin/env /opt/other/bin/python3.11\n",
			"/opt/other/lib/python3.11/site-packages/salt/_version.txt": "3007.1\n"},
			"3007.1", "3.11"},
	}
	for _, c := range cases {
		baseDir := t.TempDir()
		for path, content := range c.files {
			writeTestFile(t, baseDir, path, content)
		}
		mockExecStart(t, "/opt/salt_3006.10/bin/salt-minion", "", nil)

		minion, master := probeSaltVersions(baseDir, testTimeouts())

		if minion.err != "" || minion.version != c.version || minion.pythonVersion != c.pythonVersion || master != nil {
			t.Errorf("%s: unexpected result: %+v %v", c.name, minion, master)
		}
		if !strings.HasPrefix(minion.installPath, "/opt/") {
			t.Errorf("%s: unexpected install path %q", c.name, minion.installPath)
		}
	}
}

func TestProbeSaltVersionsOfOnedirInstall(t *testing.T) {
	cases := []struct {
		name   string
		target func(baseDir string) string
	}{
		{"absolute symlink", func(baseDir string) string { return baseDir + "/opt/saltstack/salt/salt-minion" }},
		{"relative symlink", func(baseDir string) string { return "../../opt/saltstack/salt/salt-minion" }},
	}
	for _, c := range cases {
		baseDir := t.TempDir()
		writeTestFile(t, baseDir, "/opt/saltstack/salt/salt-minion", "#!/bin/sh\n")
		writeTestFile(t, baseDir, "/opt/saltstack/salt/lib/python3.10/site-packages/salt/_version.txt", "3006.10\n")
		writeTestFile(t, baseDir, "/usr/lib/python3.9/site-packages/salt/_version.txt", "1.0\n")
		if err := os.MkdirAll(baseDir+"/usr/bin", 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(c.target(baseDir), baseDir+"/usr/bin/salt-minion"); err != nil {
			t.Fatal(err)
		}
		mockExecStart(t, "/usr/bin/salt-minion", "", nil)

		minion, _ := probeSaltVersions(baseDir, testTimeouts())

		if minion.err != "" || minion.version != "3006.10" || minion.pythonVersion != "3.10" || minion.installPath != "/opt/saltstack/salt" {
			t.Errorf("%s: unexpected result: %+v", c.name, minion)
		}
	}
}

func TestProbeSaltVersionsIgnoresAShellInterpreter(t *testing.T) {
	baseDir := t.TempDir()
	writeTestFile(t, baseDir, "/opt/s/bin/salt-minion", "#!/bin/sh\n")
	writeTestFile(t, baseDir, "/opt/s/lib/python3.10/site-packages/salt/_version.txt", "3006.10\n")
	// the prefix "/" the interpreter would name must not be searched first
	writeTestFile(t, baseDir, "/lib/python3.9/site-packages/salt/_version.txt", "1.0\n")
	mockExecStart(t, "/opt/s/bin/salt-minion", "", nil)

	minion, _ := probeSaltVersions(baseDir, testTimeouts())

	if minion.err != "" || minion.version != "3006.10" || minion.installPath != "/opt/s" {
		t.Errorf("unexpected result: %+v", minion)
	}
}

func TestProbeSaltVersionsInstallPath(t *testing.T) {
	baseDir := t.TempDir()
	writeTestFile(t, baseDir, "/opt/salt_3006.10/salt-minion", "#!/opt/salt_3006.10/bin/python3.10\n")
	writeTestFile(t, baseDir, "/opt/salt_3006.10/lib/python3.10/site-packages/salt/_version.txt", "3006.10")
	mockExecStart(t, "/opt/salt_3006.10/salt-minion", "", nil)

	minion, _ := probeSaltVersions(baseDir, testTimeouts())

	if minion.installPath != "/opt/salt_3006.10" || minion.version != "3006.10" {
		t.Errorf("unexpected result: %+v", minion)
	}
}

func TestProbeSaltVersionsFromScriptRunByInterpreter(t *testing.T) {
	baseDir := t.TempDir()
	writeTestFile(t, baseDir, "/usr/bin/salt-minion", "#!/usr/bin/python3\n")
	writeTestFile(t, baseDir, "/usr/lib/python3.9/site-packages/salt/_version.txt", "3006.9\n")
	outputs := "ExecStart={ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 /usr/bin/salt-minion -d ; ignore_errors=no }"
	mockExecStart(t, "", "", map[string]string{"/bin/systemctl show salt-minion -p ExecStart": outputs})

	minion, _ := probeSaltVersions(baseDir, testTimeouts())

	if minion.err != "" || minion.version != "3006.9" || minion.pythonVersion != "3.9" || minion.installPath != "/usr" {
		t.Errorf("unexpected result: %+v", minion)
	}
}

func TestProbeSaltVersionsPrefersTheInterpreterWhenThePackageDirHasNoMinorVersion(t *testing.T) {
	baseDir := t.TempDir()
	writeTestFile(t, baseDir, "/usr/bin/salt-minion", "#!/usr/bin/python3.11\n")
	writeTestFile(t, baseDir, "/usr/lib/python3/dist-packages/salt/_version.txt", "3006.9\n")
	mockExecStart(t, "/usr/bin/salt-minion", "", nil)

	minion, _ := probeSaltVersions(baseDir, testTimeouts())

	if minion.version != "3006.9" || minion.pythonVersion != "3.11" {
		t.Errorf("unexpected result: %+v", minion)
	}
}

func TestProbeSaltVersionsFallsBackToSaltCall(t *testing.T) {
	baseDir := t.TempDir()
	writeTestFile(t, baseDir, "/opt/salt_3006.10/bin/salt-minion", "#!/opt/salt_3006.10/bin/python3.10\n")
	mockExecStart(t, "/opt/salt_3006.10/bin/salt-minion", "", map[string]string{
		"/opt/salt_3006.10/bin/salt-call --version": "salt-call 3006.10 (Sulfur)\n",
	})
	var timeouts []time.Duration
	original := timedCommandExecutor
	timedCommandExecutor = func(timeout time.Duration, executable string, args ...string) ([]byte, error) {
		if strings.HasSuffix(executable, "salt-call") {
			timeouts = append(timeouts, timeout)
		}
		return original(timeout, executable, args...)
	}

	minion, _ := probeSaltVersions(baseDir, testTimeouts())

	if minion.err != "" || minion.version != "3006.10" || minion.pythonVersion != "3.10" || minion.installPath != "/opt/salt_3006.10" {
		t.Errorf("unexpected result: %+v", minion)
	}
	if len(timeouts) != 1 || timeouts[0] != diagConfig().SaltCallTimeout {
		t.Errorf("expected one salt-call with its timeout, got %v", timeouts)
	}
}

func TestProbeSaltVersionsErrors(t *testing.T) {
	cases := []struct {
		name     string
		outputs  map[string]string
		failing  []string
		expected string
	}{
		{"systemctl fails", nil, []string{"/bin/systemctl show salt-minion"}, "ExecStart: "},
		{"no ExecStart", map[string]string{"/bin/systemctl show salt-minion": "ExecStart="}, nil, "salt-minion has no ExecStart"},
		{"other executable", map[string]string{"/bin/systemctl show salt-minion": "ExecStart={ path=/usr/bin/foo ; argv[]=/usr/bin/foo }"}, nil, "cannot find salt-minion in ExecStart"},
		{"salt-call fails", map[string]string{"/bin/systemctl show salt-minion": fmt.Sprintf(testExecStart, "/opt/s/bin/salt-minion")},
			[]string{"/opt/s/bin/salt-call"}, "no salt package under /opt/s, Failed to execute command"},
		{"salt-call output", map[string]string{"/bin/systemctl show salt-minion": fmt.Sprintf(testExecStart, "/opt/s/bin/salt-minion"),
			"/opt/s/bin/salt-call": "Traceback..."}, nil, "unexpected salt-call output: Traceback..."},
	}
	for _, c := range cases {
		outputs := map[string]string{"/bin/systemctl show salt-master": "ExecStart="}
		for command, out := range c.outputs {
			outputs[command] = out
		}
		mockCommands(t, outputs, c.failing...)

		minion, master := probeSaltVersions(t.TempDir(), testTimeouts())

		if !strings.Contains(minion.err, c.expected) || minion.version != "" || master != nil {
			t.Errorf("%s: expected %q, got %+v %v", c.name, c.expected, minion, master)
		}
	}
}

func TestProbeSaltVersionsUnsupportedInitSystem(t *testing.T) {
	originalStat := stat
	defer func() { stat = originalStat }()
	stat = initError

	minion, master := probeSaltVersions(t.TempDir(), testTimeouts())

	if minion.err != "unsupported init system" || master != nil {
		t.Errorf("unexpected result: %+v %v", minion, master)
	}
}

func TestProbeSaltVersionsOfSaltMaster(t *testing.T) {
	baseDir := t.TempDir()
	writeTestFile(t, baseDir, "/opt/salt_3006.10/bin/salt-minion", "#!/opt/salt_3006.10/bin/python3.10\n")
	writeTestFile(t, baseDir, "/opt/salt_3006.10/lib/python3.10/site-packages/salt/_version.txt", "3006.10\n")
	writeTestFile(t, baseDir, "/opt/salt_3006.9/bin/salt-master", "#!/opt/salt_3006.9/bin/python3.10\n")
	writeTestFile(t, baseDir, "/opt/salt_3006.9/lib/python3.10/site-packages/salt/_version.txt", "3006.9\n")
	mockExecStart(t, "/opt/salt_3006.10/bin/salt-minion", "/opt/salt_3006.9/bin/salt-master", nil)

	minion, master := probeSaltVersions(baseDir, testTimeouts())

	if minion.version != "3006.10" || master == nil || master.version != "3006.9" || master.err != "" {
		t.Errorf("unexpected result: %+v %+v", minion, master)
	}
}

func TestProbeSaltVersionsOfSaltMasterWithoutUnit(t *testing.T) {
	baseDir := t.TempDir()
	writeTestFile(t, baseDir, "/opt/s/bin/salt-minion", "#!/opt/s/bin/python3.10\n")
	writeTestFile(t, baseDir, "/opt/s/lib/python3.10/site-packages/salt/_version.txt", "3006.10\n")
	// systemctl fails for the unit, and nothing else says this node has a salt-master
	mockCommands(t, map[string]string{"/bin/systemctl show salt-minion": fmt.Sprintf(testExecStart, "/opt/s/bin/salt-minion")}, "/bin/systemctl show salt-master")

	if _, master := probeSaltVersions(baseDir, testTimeouts()); master != nil {
		t.Errorf("expected no master result, got %+v", master)
	}

	// with a pki directory the node is a salt-master, so the failure is reported
	writeTestFile(t, baseDir, "/etc/salt/pki/master/master.pub", "x")
	if _, master := probeSaltVersions(baseDir, testTimeouts()); master == nil || !strings.HasPrefix(master.err, "ExecStart: ") {
		t.Errorf("expected a master error, got %+v", master)
	}
}

func TestParseExecStartExecutable(t *testing.T) {
	cases := map[string]string{
		"{ path=/opt/salt/bin/salt-minion ; argv[]=/opt/salt/bin/salt-minion -d ; ignore_errors=no }":         "/opt/salt/bin/salt-minion",
		"{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 /usr/bin/salt-minion -d ; ignore_errors=no }":      "/usr/bin/salt-minion",
		"{ path=/usr/bin/salt-minion ; argv[]=/usr/bin/salt-minion ; ignore_errors=no ; start_time=[n/a] ; }": "/usr/bin/salt-minion",
		"{ path=/bin/sh ; argv[]=/bin/sh -c exec /usr/bin/salt-minion ; ignore_errors=no }":                   "/usr/bin/salt-minion",
		"{ path=/usr/bin/other ; argv[]=/usr/bin/other ; ignore_errors=no }":                                  "",
		"": "",
	}
	for input, expected := range cases {
		if actual := parseExecStartExecutable(input, "salt-minion"); actual != expected {
			t.Errorf("parseExecStartExecutable(%q) = %q, expected %q", input, actual, expected)
		}
	}
	if actual := parseExecStartExecutable("{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 /usr/bin/salt-master -d }", "salt-master"); actual != "/usr/bin/salt-master" {
		t.Errorf("unexpected executable %q", actual)
	}
}

func TestSaltVersionSettersAreIndependentOfProbeOrder(t *testing.T) {
	minion := MinionDiagnostics{CachedId: "node1", Error: "master.conf: missing or empty"}
	master := &MasterDiagnostics{Minions: []MasterMinionDiagnostics{{Id: "node1", KeyState: "accepted"}}, KeyFingerprint: "aa"}
	versions := saltVersion{version: "3006.10", pythonVersion: "3.10", installPath: "/opt/s", err: "x"}
	masterVersion := &saltVersion{version: "3006.9"}

	versionsFirst, minionFirst := &NodeDiagnostics{}, &NodeDiagnostics{}
	versionsFirst.setSaltVersions(versions, masterVersion)
	versionsFirst.setMinion(minion)
	versionsFirst.setMaster(master)
	minionFirst.setMinion(minion)
	minionFirst.setMaster(master)
	minionFirst.setSaltVersions(versions, masterVersion)

	for _, d := range []*NodeDiagnostics{versionsFirst, minionFirst} {
		if d.Minion.CachedId != "node1" || d.Minion.Error != minion.Error || d.Minion.SaltVersion != "3006.10" || d.Minion.PythonVersion != "3.10" ||
			d.Minion.SaltInstallPath != "/opt/s" || d.Minion.VersionError != "x" {
			t.Errorf("a setter overwrote the other: %+v", d.Minion)
		}
		if len(d.Master.Minions) != 1 || d.Master.KeyFingerprint != "aa" || d.Master.SaltVersion != "3006.9" {
			t.Errorf("a setter overwrote the other: %+v", d.Master)
		}
	}

	// no master section is created on nodes that are no salt-master
	withoutMaster := &NodeDiagnostics{}
	withoutMaster.setSaltVersions(versions, nil)
	withoutMaster.setMaster(nil)
	if withoutMaster.Master != nil || withoutMaster.Minion.SaltVersion != "3006.10" {
		t.Errorf("unexpected diagnostics: %+v", withoutMaster)
	}
	b, _ := json.Marshal(NodeDiagnostics{})
	if string(b) != `{}` {
		t.Errorf("unexpected json: %s", b)
	}
}

func TestProbeMemoryReadsOomKills(t *testing.T) {
	cases := []struct {
		name     string
		vmstat   *string
		expected string
	}{
		{"oom kills", strPtr("nr_free_pages 1\noom_kill 7\n"), "7"},
		{"no kills", strPtr("oom_kill 0\n"), "0"},
		{"old kernel without the counter", strPtr("nr_free_pages 1\n"), "nil"},
		{"missing vmstat", nil, "error"},
	}
	for _, c := range cases {
		baseDir := t.TempDir()
		writeTestFile(t, baseDir, "/proc/meminfo", "MemTotal: 100 kB\nMemAvailable: 50 kB\n")
		if c.vmstat != nil {
			writeTestFile(t, baseDir, "/proc/vmstat", *c.vmstat)
		}

		memory := probeMemory(baseDir)

		switch c.expected {
		case "nil":
			if memory.OomKills != nil || memory.Error != "" {
				t.Errorf("%s: unexpected memory: %+v", c.name, memory)
			}
		case "error":
			if memory.OomKills != nil || !strings.HasPrefix(memory.Error, "vmstat: ") || *memory.TotalKb != 100 {
				t.Errorf("%s: unexpected memory: %+v", c.name, memory)
			}
		default:
			if memory.OomKills == nil || strconv.FormatUint(*memory.OomKills, 10) != c.expected || memory.Error != "" {
				t.Errorf("%s: unexpected memory: %+v", c.name, memory)
			}
		}
	}
}

func TestProbeBootTime(t *testing.T) {
	baseDir := t.TempDir()
	writeTestFile(t, baseDir, "/proc/stat", "cpu  1 2 3\nbtime 1763460000\nprocesses 99\n")

	bootTime, err := probeBootTime(baseDir)

	if err != nil || bootTime != "2025-11-18T10:00:00Z" {
		t.Errorf("unexpected boot time: %q %v", bootTime, err)
	}

	writeTestFile(t, baseDir, "/proc/stat", "cpu  1 2 3\n")
	if _, err = probeBootTime(baseDir); err == nil || err.Error() != "btime is missing" {
		t.Errorf("expected a missing btime error, got %v", err)
	}
	if _, err = probeBootTime(t.TempDir()); err == nil {
		t.Errorf("expected an error without /proc/stat")
	}
}

func TestProbeRootFilesystemReportsInodes(t *testing.T) {
	root := probeRootFilesystem(t.TempDir())

	if root.Error != "" || root.TotalBytes == nil {
		t.Fatalf("unexpected root filesystem: %+v", root)
	}
	// filesystems with a dynamic inode table report none, so only check the pair is consistent
	if (root.TotalInodes == nil) != (root.FreeInodes == nil) || (root.TotalInodes != nil && *root.FreeInodes > *root.TotalInodes) {
		t.Errorf("unexpected inodes: %+v", root)
	}
}

func TestProbeMounts(t *testing.T) {
	baseDir := t.TempDir()
	for _, dir := range []string{"/var", "/var/log", "/srv", "/tmp", "/opt"} {
		if err := os.MkdirAll(baseDir+dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	writeTestFile(t, baseDir, "/proc/self/mounts", strings.Join([]string{
		"/dev/mapper/rootvg-root / xfs rw 0 0",
		"/dev/mapper/rootvg-var-log /var/log xfs rw 0 0",
		"tmpfs /tmp tmpfs rw 0 0",
		"/dev/sdb1 /srv xfs rw 0 0",
		"/dev/sdb2 /var/lib/other xfs rw 0 0",
		"/dev/sdb3 /optional xfs rw 0 0",
		"/dev/sdb4 /opt/with\\040space xfs rw 0 0",
	}, "\n")+"\n")

	mounts, err := probeMounts(baseDir)

	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, mount := range mounts {
		paths = append(paths, mount.Path)
		if mount.Error != "" || mount.TotalBytes == nil || mount.AvailableBytes == nil {
			t.Errorf("unexpected mount: %+v", mount)
		}
	}
	// only the well-known directories that are mount points, in a stable order
	if strings.Join(paths, ",") != "/var/log,/srv,/tmp" {
		t.Errorf("unexpected mounts: %v", paths)
	}
}

func TestProbeMountsErrors(t *testing.T) {
	baseDir := t.TempDir()
	if _, err := probeMounts(baseDir); err == nil {
		t.Errorf("expected an error without the mounts file")
	}

	// a mount point that cannot be read is reported in its own entry
	writeTestFile(t, baseDir, "/proc/self/mounts", "/dev/sdb1 /var xfs rw 0 0\n")
	mounts, err := probeMounts(baseDir)
	if err != nil || len(mounts) != 1 || mounts[0].Path != "/var" || !strings.HasPrefix(mounts[0].Error, "statfs /var: ") || mounts[0].TotalBytes != nil {
		t.Errorf("unexpected mounts: %+v %v", mounts, err)
	}
}

func TestSetBootTimeAndMounts(t *testing.T) {
	d := &NodeDiagnostics{}
	d.setBootTimeAndMounts("2025-11-18T10:00:00Z", nil, nil, nil)
	if d.Resources.BootTime != "2025-11-18T10:00:00Z" || d.Resources.Disk != nil {
		t.Errorf("unexpected resources: %+v", d.Resources)
	}

	d = &NodeDiagnostics{}
	d.setBootTimeAndMounts("", errors.New("btime is missing"), nil, errors.New("no such file"))
	if d.Resources.BootTimeError != "stat: btime is missing" || d.Resources.Disk.MountsError != "mounts: no such file" {
		t.Errorf("unexpected resources: %+v", d.Resources)
	}

	// the lvm probe and the resources probe do not overwrite each other
	d = &NodeDiagnostics{}
	d.setLvm(&LvmDiagnostics{})
	d.setBootTimeAndMounts("", nil, []MountDiagnostics{{Path: "/var"}}, nil)
	if d.Resources.Disk.Lvm == nil || len(d.Resources.Disk.Mounts) != 1 {
		t.Errorf("unexpected resources: %+v", d.Resources)
	}
}

func TestCollectDiagnosticsNestsNewSections(t *testing.T) {
	withClock(t, time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC))
	mockCommands(t, map[string]string{
		"/bin/systemctl show salt-minion -p ExecStart": fmt.Sprintf(testExecStart, "/opt/s/bin/salt-minion"),
		"/bin/systemctl show salt-master -p ExecStart": "ExecStart=",
		"/bin/systemctl show":                          "LoadState=loaded\n",
		"timedatectl show":                             "NTP=yes\n",
		"hostname -s":                                  "node1",
		"hostname -f":                                  "node1.example.com",
	})
	mockHostLookup(t, func(ctx context.Context, host string) ([]string, error) { return []string{"10.0.0.5"}, nil }, nil)
	baseDir := t.TempDir()
	writeTestFile(t, baseDir, "/etc/shadow", "saltuser:$6$SECRETSALT$SECRETHASH:20765:0:90:7:::\n")
	writeTestFile(t, baseDir, "/opt/s/bin/salt-minion", "#!/opt/s/bin/python3.10\n")
	writeTestFile(t, baseDir, "/opt/s/lib/python3.10/site-packages/salt/_version.txt", "3006.10\n")
	writeTestFile(t, baseDir, "/proc/self/mounts", "/dev/sdb1 /var xfs rw 0 0\n")
	writeTestFile(t, baseDir, "/proc/stat", "btime 1763460000\n")
	writeTestFile(t, baseDir, "/proc/vmstat", "oom_kill 2\n")
	writeTestFile(t, baseDir, "/proc/meminfo", "MemTotal: 100 kB\n")
	writeTestFile(t, baseDir, "/proc/loadavg", "1.00 1.00 1.00 1/1 1\n")
	writeTestFile(t, baseDir, "/var/cache/salt/minion/proc/20261118000000000001", "")
	writeTestFile(t, baseDir, "/etc/salt/master", "worker_threads: 8\n")
	if err := os.MkdirAll(baseDir+"/var", 0755); err != nil {
		t.Fatal(err)
	}

	diagnostics := collectDiagnostics(baseDir, DiagnosticsRequest{AdditionalUnits: []string{"nginx"}, LogLines: intPtr(0)})

	b, _ := json.Marshal(diagnostics)
	for _, key := range []string{
		`"units":[{"name":"nginx"`,
		`"minion":{`, `"saltVersion":"3006.10"`, `"pythonVersion":"3.10"`, `"saltInstallPath":"/opt/s"`,
		`"saltUser":{"present":true,"locked":false`, `"passwordExpiresAt":"2027-02-06"`, `"daysUntilPasswordExpiry":80`,
		`"host":{"hostname":"node1","fqdn":"node1.example.com","fqdnAddresses":["10.0.0.5"]`,
		`"jobs":{"minionJobs":[{"jid":"20261118000000000001","startedAt":"`, `"workerThreads":8`,
		`"memory":{"totalKb":100,"oomKills":2}`, `"bootTime":"2025-11-18T10:00:00Z"`, `"mounts":[{"path":"/var","totalBytes":`,
	} {
		if !strings.Contains(string(b), key) {
			t.Errorf("expected %s in %s", key, b)
		}
	}
	if diagnostics.Master != nil || len(diagnostics.TimedOutProbes) != 0 {
		t.Errorf("expected no master section and no timed out probes: %+v", diagnostics)
	}
	for _, secret := range []string{"SECRETHASH", "SECRETSALT"} {
		if strings.Contains(string(b), secret) {
			t.Errorf("the response must not contain %q", secret)
		}
	}
}

func uint64Ptr(u uint64) *uint64 { return &u }

func float64Ptr(f float64) *float64 { return &f }

func boolPtr(b bool) *bool { return &b }

func int64Ptr(i int64) *int64 { return &i }

// healthyCluster is a salt-master that is also a minion and a plain minion, with nothing for any check to report
// except that master-keys-consistent needs a second master. Every case of the checks table changes it.
func healthyCluster() []NodeDiagnostics {
	units := func(master bool) []UnitDiagnostics {
		units := []UnitDiagnostics{{Name: "salt-minion", LoadState: "loaded", ActiveState: "active", SubState: "running"}}
		if master {
			units = append(units,
				UnitDiagnostics{Name: "salt-api", LoadState: "loaded", ActiveState: "active", SubState: "running"},
				UnitDiagnostics{Name: "salt-master", LoadState: "loaded", ActiveState: "active", SubState: "running"})
		}
		return units
	}
	node := func(address, id, fingerprint, ip string, master bool) NodeDiagnostics {
		return NodeDiagnostics{
			Address:           address,
			StatusCode:        http.StatusOK,
			ConfigFingerprint: diagConfig().fingerprint(),
			ProbeDeadline:     "10s",
			Units:             units(master),
			Minion: &MinionDiagnostics{
				Masters:                  []MinionMasterDiagnostics{{Id: "10.0.0.1", Ports: []PortDiagnostics{{Port: 4505, Reachable: true}, {Port: 4506, Reachable: true}}}},
				IdConfig:                 id,
				CachedId:                 id,
				Fingerprint:              fingerprint,
				MasterKeyFingerprint:     "masterkey",
				MasterSignKeyFingerprint: "signkey",
				SaltVersion:              "3006.10",
			},
			Host: &HostDiagnostics{Fqdn: id, FqdnAddresses: []string{ip}, Addresses: []string{ip}},
			Time: &TimeDiagnostics{Now: "2026-11-18T10:00:00Z", NtpEnabled: boolPtr(true), NtpSynchronized: boolPtr(true)},
			Jobs: &SaltJobsDiagnostics{},
			Resources: &ResourceDiagnostics{
				Load:   &LoadDiagnostics{Load5PerCpu: float64Ptr(0.5)},
				Memory: &MemoryDiagnostics{OomKills: uint64Ptr(0)},
				Disk: &DiskDiagnostics{
					Root:   &FilesystemDiagnostics{TotalBytes: uint64Ptr(1000), AvailableBytes: uint64Ptr(500), TotalInodes: uint64Ptr(1000), FreeInodes: uint64Ptr(900)},
					Mounts: []MountDiagnostics{{Path: "/var", FilesystemDiagnostics: FilesystemDiagnostics{TotalBytes: uint64Ptr(1000), AvailableBytes: uint64Ptr(500)}}},
				},
			},
		}
	}
	master := node("10.0.0.1:7071", "master.example.com", "fp-master", "10.0.0.1", true)
	master.Master = &MasterDiagnostics{
		Minions: []MasterMinionDiagnostics{
			{Id: "master.example.com", KeyState: "accepted", Fingerprint: "fp-master"},
			{Id: "node1.example.com", KeyState: "accepted", Fingerprint: "fp-node1"},
		},
		KeyFingerprint:     "masterkey",
		SignKeyFingerprint: "signkey",
		SaltVersion:        "3006.10",
	}
	master.SaltUser = &SaltUserDiagnostics{
		Present:                 true,
		DaysUntilPasswordExpiry: intPtr(80),
		Files:                   []FileDiagnostics{{Path: "/etc/passwd", Mode: "0644"}, {Path: "/etc/shadow", Mode: "0640"}, {Path: "/etc/group", Mode: "0644"}},
	}
	return []NodeDiagnostics{master, node("10.0.0.2:7071", "node1.example.com", "fp-node1", "10.0.0.2", false)}
}

func TestComputeDiagnosticsChecksOfAHealthyCluster(t *testing.T) {
	checks := computeDiagnosticsChecks(healthyCluster(), nil)

	var ids []string
	for _, check := range checks {
		ids = append(ids, check.Id)
		expected := diagnosticsCheckOk
		// a single master has nothing to compare its key with, and the healthy cluster requests no additional units
		if check.Id == "master-keys-consistent" || check.Id == "additional-units" {
			expected = diagnosticsCheckSkipped
		}
		if check.Status != expected {
			t.Errorf("expected %s to be %s, got %+v", check.Id, expected, check)
		}
	}
	expectedIds := "node-reachable,timed-out-probes,config-consistent,salt-units,additional-units,master-ports,master-keys-consistent,minion-master-key," +
		"minion-key-accepted,unknown-accepted-keys,minion-id,host-resolution,salt-version,salt-user,salt-jobs,clock,resources"
	if strings.Join(ids, ",") != expectedIds {
		t.Errorf("unexpected check ids: %s", ids)
	}
}

func TestComputeDiagnosticsChecksWithoutNodes(t *testing.T) {
	checks := computeDiagnosticsChecks(nil, nil)

	if len(checks) != 17 {
		t.Fatalf("expected an entry for every check, got %+v", checks)
	}
	for _, check := range checks {
		if check.Status != diagnosticsCheckSkipped || check.Message == "" {
			t.Errorf("expected %s to be skipped with a reason, got %+v", check.Id, check)
		}
	}
}

func TestComputeDiagnosticsChecksDoesNotDependOnTheOrderOfTheNodes(t *testing.T) {
	nodes := healthyCluster()
	nodes[0].SaltUser.Locked = true
	nodes[1].SaltUser = &SaltUserDiagnostics{}
	nodes[1].Master = &MasterDiagnostics{KeyFingerprint: "other"}
	nodes[1].Units = append(nodes[1].Units, UnitDiagnostics{Name: "salt-master", LoadState: "loaded", ActiveState: "active"})

	forward := computeDiagnosticsChecks(nodes, nil)
	backward := computeDiagnosticsChecks([]NodeDiagnostics{nodes[1], nodes[0]}, nil)

	if !reflect.DeepEqual(forward, backward) {
		t.Errorf("the order of the nodes changed the checks:\n%+v\n%+v", forward, backward)
	}
}

// multiMasterCluster has two salt-masters, which are minions too, and seven other
// nodes that have the salt-master pki directory and the inactive salt-master and salt-api units as well.
func multiMasterCluster() []NodeDiagnostics {
	unit := func(name, state, subState string) UnitDiagnostics {
		return UnitDiagnostics{Name: name, LoadState: "loaded", ActiveState: state, SubState: subState}
	}
	var nodes []NodeDiagnostics
	var minions []MasterMinionDiagnostics
	for i := 1; i <= 9; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i)
		nodes = append(nodes, NodeDiagnostics{
			Address:    ip + ":7071",
			StatusCode: http.StatusOK,
			Minion: &MinionDiagnostics{
				Masters:              []MinionMasterDiagnostics{{Id: "10.0.0.1"}, {Id: "10.0.0.2"}},
				IdConfig:             fmt.Sprintf("host%d.example.com", i),
				Fingerprint:          fmt.Sprintf("fp%d", i),
				MasterKeyFingerprint: "masterkey",
			},
			Host:   &HostDiagnostics{Fqdn: fmt.Sprintf("host%d.example.com", i), Addresses: []string{ip}},
			Time:   &TimeDiagnostics{Now: "2026-11-18T10:00:00Z", NtpEnabled: boolPtr(true), NtpSynchronized: boolPtr(true)},
			Jobs:   &SaltJobsDiagnostics{},
			Master: &MasterDiagnostics{KeyFingerprint: "masterkey"},
			Units: []UnitDiagnostics{unit("salt-minion", "active", "running"), unit("salt-api", "inactive", "dead"),
				unit("salt-master", "inactive", "dead")},
			SaltUser: &SaltUserDiagnostics{Present: false},
		})
		minions = append(minions, MasterMinionDiagnostics{Id: fmt.Sprintf("host%d.example.com", i), KeyState: "accepted", Fingerprint: fmt.Sprintf("fp%d", i)})
	}
	for _, i := range []int{0, 1} {
		nodes[i].Master.Minions = slices.Clone(minions)
		nodes[i].Units[1], nodes[i].Units[2] = unit("salt-api", "active", "running"), unit("salt-master", "active", "running")
		nodes[i].SaltUser = &SaltUserDiagnostics{Present: true, DaysUntilPasswordExpiry: intPtr(80)}
	}
	return nodes
}

func checkById(t *testing.T, checks []DiagnosticsCheck, id string) DiagnosticsCheck {
	t.Helper()
	for _, check := range checks {
		if check.Id == id {
			return check
		}
	}
	t.Fatalf("check %s not found in %+v", id, checks)
	return DiagnosticsCheck{}
}

func TestComputeDiagnosticsChecksOnlyCountsTheConfiguredMastersOfAMultiMasterCluster(t *testing.T) {
	checks := computeDiagnosticsChecks(multiMasterCluster(), nil)

	for _, id := range []string{"salt-units", "minion-key-accepted", "unknown-accepted-keys", "salt-user", "master-keys-consistent", "minion-master-key", "salt-jobs", "clock"} {
		if check := checkById(t, checks, id); check.Status != diagnosticsCheckOk {
			t.Errorf("expected %s to be ok, got %+v", id, check)
		}
	}
}

func TestComputeDiagnosticsChecksOfAMultiMasterClusterStillFindsTheBrokenMaster(t *testing.T) {
	nodes := multiMasterCluster()
	nodes[1].Units[2].ActiveState, nodes[1].Units[2].SubState = "inactive", "dead"
	nodes[1].SaltUser = &SaltUserDiagnostics{}
	nodes[1].Master.Minions = nodes[1].Master.Minions[:3]

	checks := computeDiagnosticsChecks(nodes, nil)

	if check := checkById(t, checks, "salt-units"); check.Status != diagnosticsCheckFail ||
		check.Message != "10.0.0.2: salt-master is inactive (dead)" {
		t.Errorf("unexpected salt-units: %+v", check)
	}
	if check := checkById(t, checks, "salt-user"); check.Status != diagnosticsCheckFail || check.Message != "10.0.0.2: saltuser has no entry in /etc/shadow" {
		t.Errorf("unexpected salt-user: %+v", check)
	}
	check := checkById(t, checks, "minion-key-accepted")
	expected := "master 10.0.0.2: keys absent for minions host4.example.com, host5.example.com, host6.example.com, host7.example.com, host8.example.com and 1 more"
	if check.Status != diagnosticsCheckFail || check.Message != expected {
		t.Errorf("expected one aggregated finding %q, got %+v", expected, check)
	}
	if len(check.Nodes) != 7 || check.Nodes[0] != "10.0.0.2" || check.Nodes[1] != "10.0.0.4" {
		t.Errorf("unexpected nodes of minion-key-accepted: %v", check.Nodes)
	}
}

func TestComputeDiagnosticsChecksAggregatesTheKeyStatesPerMaster(t *testing.T) {
	nodes := multiMasterCluster()
	for i := 0; i < 4; i++ {
		nodes[0].Master.Minions[i+1].KeyState = "pending"
	}
	nodes[0].Master.Minions[6].Fingerprint = "old"
	nodes[0].Master.Minions[7].Fingerprint = "old"

	check := checkById(t, computeDiagnosticsChecks(nodes, nil), "minion-key-accepted")

	expected := "master 10.0.0.1: keys pending for minions host2.example.com, host3.example.com, host4.example.com, host5.example.com; " +
		"master 10.0.0.1: different key cached for minions host7.example.com, host8.example.com"
	if check.Status != diagnosticsCheckFail || check.Message != expected {
		t.Errorf("expected %q, got %+v", expected, check)
	}
}

func TestComputeDiagnosticsChecksIdentifiesMastersByHostnameAndInterfaceAddress(t *testing.T) {
	nodes := multiMasterCluster()
	for _, node := range nodes {
		node.Minion.Masters = []MinionMasterDiagnostics{{Id: "HOST1.example.com"}, {Id: "192.168.0.2"}}
	}
	nodes[1].Host.Addresses = []string{"192.168.0.2"}
	nodes[1].Address = "unrelated:7071"

	masters := saltMasters(nodes)

	if len(masters) != 2 || masters[0].Address != "10.0.0.1:7071" || masters[1].Address != "unrelated:7071" {
		t.Errorf("unexpected masters %+v", masters)
	}
}

func TestSaltMastersFallsBackToTheUnitAndTheSaltUserWithoutMasterConf(t *testing.T) {
	nodes := multiMasterCluster()
	for i := range nodes {
		nodes[i].Minion = nil
	}
	nodes[5].SaltUser = &SaltUserDiagnostics{Present: true}
	nodes[6].Units = nil
	nodes[6].Master = nil
	nodes[6].SaltUser = &SaltUserDiagnostics{Present: true}

	var addresses []string
	for _, master := range saltMasters(nodes) {
		addresses = append(addresses, master.Address)
	}

	expected := []string{"10.0.0.1:7071", "10.0.0.2:7071", "10.0.0.6:7071"}
	if !reflect.DeepEqual(addresses, expected) {
		t.Errorf("expected %v, got %v", expected, addresses)
	}
}

func TestComputeDiagnosticsChecksTreatsAnAddressWithoutPortAsItIs(t *testing.T) {
	nodes := multiMasterCluster()
	nodes[0].Address = "10.0.0.1"

	if masters := saltMasters(nodes); len(masters) != 2 || masters[0].Address != "10.0.0.1" {
		t.Errorf("unexpected masters %+v", masters)
	}
}

func TestComputeDiagnosticsChecks(t *testing.T) {
	// the checks name the nodes by host; the fixtures of healthyCluster are reached at host:7071
	const master, minion = "10.0.0.1", "10.0.0.2"
	secondMaster := func(nodes []NodeDiagnostics) []NodeDiagnostics {
		second := healthyCluster()[0]
		second.Address = "10.0.0.3:7071"
		second.Host.Addresses, second.Host.FqdnAddresses = []string{"10.0.0.3"}, []string{"10.0.0.3"}
		for _, node := range nodes {
			node.Minion.Masters = append(node.Minion.Masters, MinionMasterDiagnostics{Id: "10.0.0.3"})
		}
		return append(nodes, second)
	}
	// a third node with its own clock; the median of the clocks is the one of the healthy nodes
	thirdNode := func(now string) func(nodes []NodeDiagnostics) []NodeDiagnostics {
		return func(nodes []NodeDiagnostics) []NodeDiagnostics {
			third := healthyCluster()[1]
			third.Address, third.Time.Now = "10.0.0.3:7071", now
			return append(nodes, third)
		}
	}
	// the third node was contacted offset after the first one, e.g. because it waited for a free slot of the fan-out
	delayedThirdNode := func(now string, offset time.Duration) func(nodes []NodeDiagnostics) []NodeDiagnostics {
		return func(nodes []NodeDiagnostics) []NodeDiagnostics {
			nodes = thirdNode(now)(nodes)
			nodes[2].contactOffset = offset
			return nodes
		}
	}
	// the master probe of the master timed out or panicked, so only the saltVersion probe left a master section
	masterProbeLost := func(timedOut bool) func(nodes []NodeDiagnostics) []NodeDiagnostics {
		return func(nodes []NodeDiagnostics) []NodeDiagnostics {
			nodes[0].Master = &MasterDiagnostics{Minions: []MasterMinionDiagnostics{}, SaltVersion: "3006.10"}
			if timedOut {
				nodes[0].TimedOutProbes = []string{"master"}
			} else {
				nodes[0].FailedProbes = []string{"master: runtime error: index out of range"}
			}
			return nodes
		}
	}
	acceptedMinions := func(count int) []MasterMinionDiagnostics {
		var minions []MasterMinionDiagnostics
		for i := 0; i < count; i++ {
			minions = append(minions, MasterMinionDiagnostics{Id: fmt.Sprintf("minion%d.example.com", i), KeyState: "accepted"})
		}
		return minions
	}
	cases := []struct {
		name    string
		id      string
		units   []string
		mutate  func(nodes []NodeDiagnostics) []NodeDiagnostics
		status  string
		message string
		nodes   []string
	}{
		{name: "reachable", id: "node-reachable", status: "ok", message: "2 nodes answered"},
		{name: "older salt-bootstrap", id: "node-reachable", status: "warn", message: minion + ": 404, older salt-bootstrap", nodes: []string{minion},
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1] = NodeDiagnostics{Address: minion, StatusCode: 404, ErrorText: "unexpected response: 404 page not found"}
				return n
			}},
		{name: "unreachable", id: "node-reachable", status: "fail", message: minion + ": status 500: dial tcp: no route to host",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1] = NodeDiagnostics{Address: minion, StatusCode: 500, ErrorText: "dial tcp: no route to host"}
				return n
			}},
		{name: "unreachable beats older", id: "node-reachable", status: "fail", nodes: []string{minion, master},
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0] = NodeDiagnostics{Address: master, StatusCode: 404}
				n[1] = NodeDiagnostics{Address: minion, StatusCode: 502}
				return n
			}},
		{name: "no nodes", id: "node-reachable", status: "skipped", message: "no nodes",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { return nil }},

		{name: "no timeouts", id: "timed-out-probes", status: "ok"},
		{name: "timed out probes", id: "timed-out-probes", status: "warn", message: master + ": probes timed out: host, lvm", nodes: []string{master},
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { n[0].TimedOutProbes = []string{"host", "lvm"}; return n }},
		{name: "no node answered", id: "timed-out-probes", status: "skipped",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { n[0].StatusCode, n[1].StatusCode = 500, 500; return n }},

		{name: "same configuration", id: "config-consistent", status: "ok", message: "nodes use the diagnostics configuration of the fan-out node"},
		{name: "probe deadline not below the fan-out timeout", id: "config-consistent", status: "fail", nodes: []string{minion},
			message: minion + ": probeDeadline 20s leaves less than 1s of the distributeTimeout 20s of the fan-out node for the response",
			mutate:  func(n []NodeDiagnostics) []NodeDiagnostics { n[1].ProbeDeadline = "20s"; return n }},
		{name: "probe deadline within the response margin", id: "config-consistent", status: "fail", nodes: []string{minion},
			message: minion + ": probeDeadline 19.5s leaves less than 1s of the distributeTimeout 20s of the fan-out node for the response",
			mutate:  func(n []NodeDiagnostics) []NodeDiagnostics { n[1].ProbeDeadline = "19.5s"; return n }},
		{name: "probe deadline leaving exactly the margin", id: "config-consistent", status: "ok",
			message: "nodes use the diagnostics configuration of the fan-out node",
			mutate:  func(n []NodeDiagnostics) []NodeDiagnostics { n[1].ProbeDeadline = "19s"; return n }},
		{name: "configuration differs on two nodes", id: "config-consistent", status: "warn", nodes: []string{master, minion},
			message: "diagnostics configuration differs from the fan-out node on 2 nodes",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0].ConfigFingerprint, n[1].ConfigFingerprint = "other", "other"
				return n
			}},
		{name: "unusable configuration", id: "config-consistent", status: "warn", nodes: []string{minion},
			message: minion + ": diagnostics configuration not usable, defaults in use: /etc/salt-bootstrap/diagnostics.yml: field x not found",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].ConfigError = "/etc/salt-bootstrap/diagnostics.yml: field x not found"
				return n
			}},
		{name: "configuration of older salt-bootstraps", id: "config-consistent", status: "skipped", message: "no node reports its diagnostics configuration",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0].ConfigFingerprint, n[1].ConfigFingerprint = "", ""
				return n
			}},

		{name: "units active", id: "salt-units", status: "ok"},
		{name: "crash-looping minion between two crashes", id: "salt-units", status: "fail", nodes: []string{minion},
			message: minion + ": salt-minion is crash-looping: restarted 33 times, the current process is up 1s",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Units[0] = UnitDiagnostics{Name: "salt-minion", LoadState: "loaded", ActiveState: "active", SubState: "running", NRestarts: intPtr(33),
					MainPid: intPtr(42896), Process: &ProcessDiagnostics{State: "S (sleeping)", UptimeSeconds: int64Ptr(1)}}
				return n
			}},
		{name: "minion restarted long ago", id: "salt-units", status: "ok",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Units[0] = UnitDiagnostics{Name: "salt-minion", LoadState: "loaded", ActiveState: "active", SubState: "running", NRestarts: intPtr(33),
					MainPid: intPtr(42896), Process: &ProcessDiagnostics{State: "S (sleeping)", UptimeSeconds: int64Ptr(7200)}}
				return n
			}},
		{name: "minion restarted twice just now", id: "salt-units", status: "ok",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Units[0] = UnitDiagnostics{Name: "salt-minion", LoadState: "loaded", ActiveState: "active", SubState: "running", NRestarts: intPtr(2),
					MainPid: intPtr(42896), Process: &ProcessDiagnostics{State: "S (sleeping)", UptimeSeconds: int64Ptr(1)}}
				return n
			}},
		{name: "crash-looping requested unit", id: "additional-units", units: []string{"example-agent"}, status: "warn", nodes: []string{minion},
			message: minion + ": example-agent is crash-looping: restarted 5 times, the current process is up 3s",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Units = append(n[1].Units, UnitDiagnostics{Name: "example-agent", LoadState: "loaded", ActiveState: "active",
					NRestarts: intPtr(5), Process: &ProcessDiagnostics{UptimeSeconds: int64Ptr(3)}})
				return n
			}},
		{name: "minion inactive", id: "salt-units", status: "fail", message: minion + ": salt-minion is inactive (dead)", nodes: []string{minion},
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Units[0].ActiveState, n[1].Units[0].SubState = "inactive", "dead"
				return n
			}},
		{name: "master and api inactive on a master", id: "salt-units", status: "fail", message: "salt-api is failed (failed); " + master + ": salt-master is inactive",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0].Units[1].ActiveState, n[0].Units[1].SubState = "failed", "failed"
				n[0].Units[2].ActiveState = "inactive"
				return n
			}},
		{name: "absent salt-api of a master", id: "salt-units", status: "ok",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0].Units[1] = UnitDiagnostics{Name: "salt-api", LoadState: "not-found"}
				return n
			}},
		{name: "inactive salt-master of a node that is no master", id: "salt-units", status: "ok",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Units = append(n[1].Units, UnitDiagnostics{Name: "salt-master", LoadState: "loaded", ActiveState: "inactive"})
				return n
			}},
		{name: "requested unit inactive", id: "additional-units", units: []string{"nginx"}, status: "warn", message: minion + ": nginx is inactive (dead)",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Units = append(n[1].Units, UnitDiagnostics{Name: "nginx", LoadState: "loaded", ActiveState: "inactive", SubState: "dead"})
				return n
			}},
		{name: "requested unit not found", id: "additional-units", units: []string{"nginx"}, status: "warn", message: minion + ": nginx not found",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Units = append(n[1].Units, UnitDiagnostics{Name: "nginx", LoadState: "not-found", ActiveState: "inactive"})
				return n
			}},
		{name: "requested unit inactive is no salt unit problem", id: "salt-units", units: []string{"nginx"}, status: "ok",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Units = append(n[1].Units, UnitDiagnostics{Name: "nginx", LoadState: "loaded", ActiveState: "inactive", SubState: "dead"})
				return n
			}},
		{name: "requested unit with the service suffix", id: "additional-units", units: []string{"example-agent.service"}, status: "warn",
			nodes:   []string{master, minion},
			message: "example-agent is inactive (dead) on 2 nodes",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				for i := range n {
					n[i].Units = append(n[i].Units, UnitDiagnostics{Name: "example-agent", LoadState: "loaded", ActiveState: "inactive", SubState: "dead"})
				}
				return n
			}},
		{name: "requested unit active", id: "additional-units", units: []string{"nginx", "nginx"}, status: "ok", message: "additional units are active",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Units = append(n[1].Units, UnitDiagnostics{Name: "nginx", LoadState: "loaded", ActiveState: "active", SubState: "running"})
				return n
			}},
		{name: "requested unit failed on two nodes", id: "additional-units", units: []string{"nginx"}, status: "warn", nodes: []string{master, minion},
			message: master + ": nginx is failed (failed); " + minion + ": nginx state unknown: boom",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0].Units = append(n[0].Units, UnitDiagnostics{Name: "nginx", LoadState: "loaded", ActiveState: "failed", SubState: "failed"})
				n[1].Units = append(n[1].Units, UnitDiagnostics{Name: "nginx", Error: "boom"})
				return n
			}},
		{name: "requested unit with the same problem on two nodes", id: "additional-units", units: []string{"example-agent"}, status: "warn",
			nodes:   []string{master, minion},
			message: "example-agent is inactive (dead) on 2 nodes",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				for i := range n {
					n[i].Units = append(n[i].Units, UnitDiagnostics{Name: "example-agent", LoadState: "loaded", ActiveState: "inactive", SubState: "dead"})
				}
				return n
			}},
		{name: "rejected unit on two nodes", id: "additional-units", units: []string{"salt-*", "example-agent"}, status: "fail",
			nodes:   []string{master, minion},
			message: "salt-* rejected: not a plain systemd unit name on 2 nodes; example-agent is inactive (dead) on 2 nodes",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				for i := range n {
					n[i].Units = append(n[i].Units, UnitDiagnostics{Name: "salt-*", Rejected: "not a plain systemd unit name"},
						UnitDiagnostics{Name: "example-agent", LoadState: "loaded", ActiveState: "inactive", SubState: "dead"})
				}
				return n
			}},
		{name: "no additional units requested", id: "additional-units", status: "skipped", message: "no additional units requested",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Units = append(n[1].Units, UnitDiagnostics{Name: "nginx", LoadState: "loaded", ActiveState: "failed"})
				return n
			}},
		{name: "only salt units requested", id: "additional-units", units: []string{"salt-master", "salt-minion.service"}, status: "skipped",
			message: "no additional units requested"},
		{name: "requested unit without unit data", id: "additional-units", units: []string{"nginx"}, status: "skipped", message: "no unit state reported",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { n[0].Units, n[1].Units = nil, nil; return n }},
		{name: "salt-bootstrap active", id: "salt-units", status: "ok",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Units = append(n[1].Units, UnitDiagnostics{Name: "salt-bootstrap", LoadState: "loaded", ActiveState: "active", SubState: "running"})
				return n
			}},
		{name: "salt-bootstrap not running as its unit", id: "salt-units", status: "warn", nodes: []string{minion},
			message: minion + ": salt-bootstrap is inactive (dead)",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Units = append(n[1].Units, UnitDiagnostics{Name: "salt-bootstrap", LoadState: "loaded", ActiveState: "inactive", SubState: "dead"})
				return n
			}},
		{name: "salt-bootstrap unit not found", id: "salt-units", status: "warn", message: master + ": salt-bootstrap not found",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0].Units = append(n[0].Units, UnitDiagnostics{Name: "salt-bootstrap", LoadState: "not-found"})
				return n
			}},
		{name: "requested salt-bootstrap is no additional unit", id: "additional-units", units: []string{"salt-bootstrap"}, status: "skipped",
			message: "no additional units requested"},
		{name: "unit that was not requested", id: "salt-units", status: "ok",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Units = append(n[1].Units, UnitDiagnostics{Name: "nginx", LoadState: "loaded", ActiveState: "failed"})
				return n
			}},
		{name: "pki directory of a node that is no configured master", id: "salt-units", status: "ok",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Master = &MasterDiagnostics{KeyFingerprint: "masterkey"}
				n[1].Units = append(n[1].Units,
					UnitDiagnostics{Name: "salt-master", LoadState: "loaded", ActiveState: "inactive", SubState: "dead"},
					UnitDiagnostics{Name: "salt-api", LoadState: "loaded", ActiveState: "inactive", SubState: "dead"})
				return n
			}},
		{name: "requested salt-master inactive on a node that is no master", id: "salt-units", units: []string{"salt-master"}, status: "warn",
			message: minion + ": salt-master is inactive (dead)",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Master = &MasterDiagnostics{}
				n[1].Units = append(n[1].Units, UnitDiagnostics{Name: "salt-master", LoadState: "loaded", ActiveState: "inactive", SubState: "dead"})
				return n
			}},
		{name: "configured master with a dead salt-master", id: "salt-units", status: "fail", nodes: []string{master},
			message: master + ": salt-master is failed (failed)",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0].Units[2].ActiveState, n[0].Units[2].SubState = "failed", "failed"
				return n
			}},
		{name: "configured master with a not-found salt-master", id: "salt-units", status: "fail", message: master + ": salt-master not found", nodes: []string{master},
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0].Units[2] = UnitDiagnostics{Name: "salt-master", LoadState: "not-found"}
				return n
			}},
		{name: "configured master without a salt-master unit", id: "salt-units", status: "fail", message: master + ": salt-master not found",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { n[0].Units = n[0].Units[:2]; return n }},
		{name: "configured master with the units timed out", id: "salt-units", status: "ok",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0].Units, n[0].TimedOutProbes = n[0].Units[:1], []string{"units"}
				return n
			}},
		{name: "node with a master section is no master for the keys", id: "salt-user", status: "ok",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Master = &MasterDiagnostics{KeyFingerprint: "stale"}
				return n
			}},
		{name: "unit state unknown", id: "salt-units", status: "warn", message: minion + ": salt-minion state unknown: unsupported init system",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Units = []UnitDiagnostics{{Name: "salt-minion", Error: "unsupported init system"}}
				return n
			}},
		{name: "minion in uninterruptible I/O wait", id: "salt-units", status: "warn", nodes: []string{minion},
			message: minion + ": salt-minion main process is in uninterruptible I/O wait (D state)",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Units[0].Process = &ProcessDiagnostics{State: "D (disk sleep)"}
				return n
			}},
		{name: "salt-api in uninterruptible I/O wait", id: "salt-units", status: "warn", message: master + ": salt-api main process is in uninterruptible I/O wait",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0].Units[1].Process = &ProcessDiagnostics{State: "D (disk sleep)"}
				return n
			}},
		{name: "salt-master in uninterruptible I/O wait", id: "salt-units", status: "warn", message: master + ": salt-master main process is in uninterruptible I/O wait",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0].Units[2].Process = &ProcessDiagnostics{State: "D (disk sleep)"}
				return n
			}},
		{name: "sleeping minion process", id: "salt-units", status: "ok",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Units[0].Process = &ProcessDiagnostics{State: "S (sleeping)"}
				return n
			}},
		{name: "other unit in uninterruptible I/O wait", id: "salt-units", status: "ok",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Units = append(n[1].Units, UnitDiagnostics{Name: "nginx", LoadState: "loaded", ActiveState: "active", Process: &ProcessDiagnostics{State: "D (disk sleep)"}})
				return n
			}},
		{name: "no units", id: "salt-units", status: "skipped",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { n[0].Units, n[1].Units = nil, nil; return n }},

		{name: "ports reachable", id: "master-ports", status: "ok"},
		{name: "port unreachable", id: "master-ports", status: "fail", message: minion + ": master 10.0.0.1 port 4506 unreachable", nodes: []string{minion},
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Minion.Masters[0].Ports[1].Reachable = false
				return n
			}},
		{name: "master unreachable from every node", id: "master-ports", status: "fail", nodes: []string{master, minion},
			message: "master 10.0.0.1 ports 4505,4506 unreachable from 2 nodes",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				for i := range n {
					n[i].Minion.Masters[0].Ports[0].Reachable, n[i].Minion.Masters[0].Ports[1].Reachable = false, false
				}
				return n
			}},
		{name: "both ports unreachable", id: "master-ports", status: "fail", message: "ports 4505,4506 unreachable",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Minion.Masters[0].Ports[0].Reachable, n[1].Minion.Masters[0].Ports[1].Reachable = false, false
				return n
			}},
		{name: "no ports checked", id: "master-ports", status: "skipped",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0].Minion.Masters, n[1].Minion.Masters = nil, nil
				return n
			}},

		{name: "one master key", id: "master-keys-consistent", status: "skipped", message: "fewer than two"},
		{name: "same master key", id: "master-keys-consistent", status: "ok", mutate: secondMaster},
		{name: "different master keys", id: "master-keys-consistent", status: "fail", nodes: []string{master, "10.0.0.3"},
			message: master + ": master key masterkey differs between masters; 10.0.0.3: master key other differs between masters",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n = secondMaster(n)
				n[2].Master = &MasterDiagnostics{KeyFingerprint: "other"}
				return n
			}},
		{name: "second master has no key", id: "master-keys-consistent", status: "skipped",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n = secondMaster(n)
				n[2].Master = &MasterDiagnostics{}
				return n
			}},

		{name: "master probe timed out for the key comparison", id: "master-keys-consistent", status: "warn", nodes: []string{master},
			message: master + ": master probe timed out, keys not checked",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				return masterProbeLost(true)(secondMaster(n))
			}},
		{name: "master probe timed out for the master key", id: "minion-master-key", status: "warn", nodes: []string{master},
			message: master + ": master probe timed out, keys not checked", mutate: masterProbeLost(true)},
		{name: "master key mismatch while another master is unknown", id: "minion-master-key", status: "warn", nodes: []string{master, minion},
			message: master + ": master probe failed, keys not checked; " + minion + ": master key stale matches no target master",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n = masterProbeLost(false)(secondMaster(n))
				n[1].Minion.MasterKeyFingerprint = "stale"
				return n
			}},

		{name: "minions hold the master key", id: "minion-master-key", status: "ok"},
		{name: "minion holds another master key", id: "minion-master-key", status: "fail", message: minion + ": master key stale matches no target master", nodes: []string{minion},
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { n[1].Minion.MasterKeyFingerprint = "stale"; return n }},
		{name: "minion holds a key of the second master", id: "minion-master-key", status: "ok",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n = secondMaster(n)
				n[2].Master = &MasterDiagnostics{KeyFingerprint: "other"}
				n[1].Minion.MasterKeyFingerprint = "other"
				return n
			}},
		{name: "minion has no master key", id: "minion-master-key", status: "warn", message: minion + ": no master key fingerprint",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { n[1].Minion.MasterKeyFingerprint = ""; return n }},
		{name: "minion holds another sign key", id: "minion-master-key", status: "fail", message: minion + ": master sign key stale matches no target master",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { n[1].Minion.MasterSignKeyFingerprint = "stale"; return n }},
		{name: "masters sign no key", id: "minion-master-key", status: "ok",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { n[0].Master.SignKeyFingerprint = ""; return n }},
		{name: "no master key to compare", id: "minion-master-key", status: "skipped",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { n[0].Master = nil; return n }},

		{name: "keys accepted", id: "minion-key-accepted", status: "ok"},
		{name: "master caches another key", id: "minion-key-accepted", status: "fail", nodes: []string{master, minion},
			message: "master " + master + ": different key cached for minions node1.example.com",
			mutate:  func(n []NodeDiagnostics) []NodeDiagnostics { n[0].Master.Minions[1].Fingerprint = "old"; return n }},
		{name: "key pending", id: "minion-key-accepted", status: "fail", message: "master " + master + ": keys pending for minions node1.example.com",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { n[0].Master.Minions[1].KeyState = "pending"; return n }},
		{name: "key rejected", id: "minion-key-accepted", status: "fail", message: "keys rejected for minions",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { n[0].Master.Minions[1].KeyState = "rejected"; return n }},
		{name: "key denied", id: "minion-key-accepted", status: "fail", message: "keys denied for minions",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { n[0].Master.Minions[1].KeyState = "denied"; return n }},
		{name: "key absent", id: "minion-key-accepted", status: "fail", message: "keys absent for minions node1.example.com",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { n[0].Master.Minions = n[0].Master.Minions[:1]; return n }},
		{name: "master probe timed out for the keys", id: "minion-key-accepted", status: "warn", nodes: []string{master},
			message: master + ": master probe timed out, keys not checked", mutate: masterProbeLost(true)},
		{name: "master probe failed for the keys", id: "minion-key-accepted", status: "warn", nodes: []string{master},
			message: master + ": master probe failed, keys not checked", mutate: masterProbeLost(false)},
		{name: "keys of the second master are still checked", id: "minion-key-accepted", status: "fail", nodes: []string{master, minion, "10.0.0.3"},
			message: "master " + master + ": keys absent for minions node1.example.com; 10.0.0.3: master probe timed out, keys not checked",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n = secondMaster(n)
				n[2].Master = &MasterDiagnostics{Minions: []MasterMinionDiagnostics{}}
				n[2].TimedOutProbes = []string{"master"}
				n[0].Master.Minions = n[0].Master.Minions[:1]
				return n
			}},
		{name: "key unknown on a master with an error", id: "minion-key-accepted", status: "warn", nodes: []string{minion, master},
			message: minion + ": key of minion node1.example.com unknown on master " + master + ": open /etc/salt/pki/master/minions: permission denied",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0].Master.Minions = n[0].Master.Minions[:1]
				n[0].Master.Error = "open /etc/salt/pki/master/minions: permission denied\nmore"
				return n
			}},
		{name: "key absent on the second master", id: "minion-key-accepted", status: "fail", nodes: []string{"10.0.0.3", minion},
			message: "master 10.0.0.3: keys absent for minions node1.example.com",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n = secondMaster(n)
				n[2].Master = &MasterDiagnostics{Minions: []MasterMinionDiagnostics{{Id: "master.example.com", KeyState: "accepted", Fingerprint: "fp-master"}}}
				return n
			}},
		{name: "unreadable accepted key", id: "minion-key-accepted", status: "ok",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0].Master.Minions[1].Fingerprint, n[0].Master.Minions[1].Error = "", "fingerprint: cannot decode public key"
				return n
			}},
		{name: "minion key id is the cached one", id: "minion-key-accepted", status: "fail", message: "keys absent for minions cached.example.com",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Minion.IdConfig, n[1].Minion.CachedId = "", "cached.example.com"
				return n
			}},
		{name: "no master for the keys", id: "minion-key-accepted", status: "skipped", message: "no salt-master",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { return n[1:] }},
		{name: "no minion fingerprint", id: "minion-key-accepted", status: "skipped", message: "no minion with a key fingerprint",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0].Minion.Fingerprint, n[1].Minion.Fingerprint = "", ""
				return n
			}},

		{name: "all accepted keys known", id: "unknown-accepted-keys", status: "ok"},
		{name: "master probe timed out for the unknown keys", id: "unknown-accepted-keys", status: "warn", nodes: []string{master},
			message: master + ": master probe timed out, keys not checked", mutate: masterProbeLost(true)},
		{name: "unknown accepted key", id: "unknown-accepted-keys", status: "warn", nodes: []string{master},
			message: master + ": accepted keys of unknown minions: old-node (expected if only a subset of the cluster was targeted)",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0].Master.Minions = append(n[0].Master.Minions, MasterMinionDiagnostics{Id: "old-node", KeyState: "accepted"})
				return n
			}},
		{name: "many unknown accepted keys", id: "unknown-accepted-keys", status: "warn", message: "a, b, c, d, e and 2 more",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				for _, id := range []string{"a", "b", "c", "d", "e", "f", "g"} {
					n[0].Master.Minions = append(n[0].Master.Minions, MasterMinionDiagnostics{Id: id, KeyState: "accepted"})
				}
				return n
			}},
		{name: "unknown pending key", id: "unknown-accepted-keys", status: "ok",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0].Master.Minions = append(n[0].Master.Minions, MasterMinionDiagnostics{Id: "old-node", KeyState: "pending"})
				return n
			}},
		{name: "no master for unknown keys", id: "unknown-accepted-keys", status: "skipped",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { return n[1:] }},
		{name: "no minion ids", id: "unknown-accepted-keys", status: "skipped",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { n[0].Minion, n[1].Minion = nil, nil; return n }},

		{name: "ids unique", id: "minion-id", status: "ok"},
		{name: "configured and cached id differ", id: "minion-id", status: "fail", nodes: []string{minion},
			message: minion + ": minion id node1.example.com in minion_id.conf differs from the cached id node1",
			mutate:  func(n []NodeDiagnostics) []NodeDiagnostics { n[1].Minion.CachedId = "node1"; return n }},
		{name: "duplicate ids", id: "minion-id", status: "fail", nodes: []string{master, minion},
			message: "minion id master.example.com is used by " + master + ", " + minion,
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Minion.IdConfig, n[1].Minion.CachedId, n[1].Host.Fqdn = "master.example.com", "", "master.example.com"
				return n
			}},
		{name: "id differs from the FQDN", id: "minion-id", status: "warn", message: minion + ": minion id node1.example.com differs from the FQDN node1.internal",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { n[1].Host.Fqdn = "node1.internal"; return n }},
		{name: "no ids", id: "minion-id", status: "skipped",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { n[0].Minion, n[1].Minion = nil, nil; return n }},

		{name: "FQDN resolves", id: "host-resolution", status: "ok"},
		{name: "FQDN does not resolve", id: "host-resolution", status: "fail", message: minion + ": FQDN node1.example.com does not resolve: no such host", nodes: []string{minion},
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Host.FqdnAddresses, n[1].Host.FqdnError = nil, "no such host"
				return n
			}},
		{name: "hostname -f failed", id: "host-resolution", status: "fail", message: minion + ": hostname -f failed: exit status 1", nodes: []string{minion},
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Host.Fqdn, n[1].Host.FqdnAddresses, n[1].Host.Error = "", nil, "hostname: x; fqdn: exit status 1; hosts: y"
				return n
			}},
		{name: "FQDN resolves to another address", id: "host-resolution", status: "fail", message: "resolves to [10.0.0.9], not to an address of the node [10.0.0.2]",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { n[1].Host.FqdnAddresses = []string{"10.0.0.9"}; return n }},
		{name: "FQDN resolves to one of several addresses", id: "host-resolution", status: "ok",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Host.Addresses = []string{"192.168.0.2", "fe80:0:0:0:0:0:0:2", "10.0.0.2"}
				n[1].Host.FqdnAddresses = []string{"fe80::2"}
				return n
			}},
		{name: "hosts without trailing newline", id: "host-resolution", status: "warn", message: master + ": /etc/hosts has no trailing newline",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { n[0].Host.HostsMissingTrailingNewline = true; return n }},
		{name: "FQDN is the short name", id: "host-resolution", status: "warn", nodes: []string{minion},
			message: minion + ": hostname -f returns the short name node1; the node may register with its short hostname",
			mutate:  func(n []NodeDiagnostics) []NodeDiagnostics { n[1].Host.Fqdn = "node1"; return n }},
		{name: "no FQDN is no short name", id: "host-resolution", status: "fail", message: minion + ": hostname -f failed: exit status 1",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Host.Fqdn, n[1].Host.FqdnAddresses, n[1].Host.Error = "", nil, "fqdn: exit status 1"
				return n
			}},
		{name: "no host data", id: "host-resolution", status: "skipped",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { n[0].Host, n[1].Host = nil, nil; return n }},

		{name: "same version", id: "salt-version", status: "ok"},
		{name: "mixed versions", id: "salt-version", status: "warn", message: "mixed minion versions: 3006.10 (" + master + "), 3001.8 (" + minion + ")", nodes: []string{master, minion},
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { n[1].Minion.SaltVersion = "3001.8"; return n }},
		{name: "minion newer than master", id: "salt-version", status: "fail", message: minion + ": minion 3006.10 is newer than the salt-master " + master + " (3006.9)",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0].Master.SaltVersion, n[0].Minion.SaltVersion = "3006.9", "3006.9"
				return n
			}},
		{name: "minion older than master", id: "salt-version", status: "warn", message: "mixed minion versions",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { n[1].Minion.SaltVersion = "3001.8"; return n }},
		{name: "no versions", id: "salt-version", status: "skipped",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0].Minion.SaltVersion, n[1].Minion.SaltVersion = "", ""
				return n
			}},

		{name: "saltuser fine", id: "salt-user", status: "ok"},
		{name: "no masters", id: "salt-user", status: "skipped", mutate: func(n []NodeDiagnostics) []NodeDiagnostics { return n[1:] }},
		{name: "no saltuser section", id: "salt-user", status: "fail", message: master + ": saltuser has no entry in /etc/shadow", nodes: []string{master},
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { n[0].SaltUser = nil; return n }},
		{name: "saltuser probe timed out", id: "salt-user", status: "warn", message: master + ": saltUser probe timed out", nodes: []string{master},
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0].SaltUser, n[0].TimedOutProbes = nil, []string{"saltUser"}
				return n
			}},
		{name: "shadow unreadable", id: "salt-user", status: "fail", message: master + ": saltuser entry not readable in /etc/shadow: open /etc/shadow: permission denied", nodes: []string{master},
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0].SaltUser = &SaltUserDiagnostics{Error: "open /etc/shadow: permission denied"}
				return n
			}},
		{name: "saltuser not present", id: "salt-user", status: "fail", message: "saltuser has no entry",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { n[0].SaltUser.Present = false; return n }},
		{name: "locked", id: "salt-user", status: "fail", message: master + ": account locked",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { n[0].SaltUser.Locked = true; return n }},
		{name: "empty password", id: "salt-user", status: "fail", message: master + ": empty password",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { n[0].SaltUser.EmptyPassword = true; return n }},
		{name: "password differs from the request", id: "salt-user", status: "fail", nodes: []string{master},
			message: master + ": password does not match",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0].SaltUser.PasswordCheck, n[0].SaltUser.PasswordHashScheme = "mismatch", "sha512"
				return n
			}},
		{name: "password set by passwd with yescrypt", id: "salt-user", status: "warn", nodes: []string{master},
			message: master + ": password cannot be checked: yescrypt hash, which salt-bootstrap does not write",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0].SaltUser.PasswordCheck, n[0].SaltUser.PasswordHashScheme = "unverifiable", "yescrypt"
				return n
			}},
		{name: "password matches the request", id: "salt-user", status: "ok",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0].SaltUser.PasswordCheck, n[0].SaltUser.PasswordHashScheme = "match", "sha512"
				return n
			}},
		{name: "password expired", id: "salt-user", status: "fail", message: master + ": password expired 2026-07-13",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0].SaltUser.PasswordExpired, n[0].SaltUser.PasswordExpiresAt, n[0].SaltUser.DaysUntilPasswordExpiry = true, "2026-07-13", intPtr(-3)
				return n
			}},
		{name: "account expired", id: "salt-user", status: "fail", message: master + ": account expired 2026-01-01",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0].SaltUser.AccountExpired, n[0].SaltUser.AccountExpiresAt = true, "2026-01-01"
				return n
			}},
		{name: "password change required", id: "salt-user", status: "fail", message: master + ": password change required",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { n[0].SaltUser.PasswordChangeRequired = true; return n }},
		{name: "password expires soon", id: "salt-user", status: "warn", message: master + ": password expires in 13 days, on 2026-12-01",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0].SaltUser.DaysUntilPasswordExpiry, n[0].SaltUser.PasswordExpiresAt = intPtr(13), "2026-12-01"
				return n
			}},
		{name: "password expires in two weeks", id: "salt-user", status: "ok",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0].SaltUser.DaysUntilPasswordExpiry = intPtr(14)
				return n
			}},
		{name: "password never expires", id: "salt-user", status: "ok",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { n[0].SaltUser.DaysUntilPasswordExpiry = nil; return n }},
		{name: "faillock failures", id: "salt-user", status: "warn", message: master + ": 3 failed logins held by faillock",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { n[0].SaltUser.FaillockFailures = intPtr(3); return n }},
		{name: "no faillock failures", id: "salt-user", status: "ok",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { n[0].SaltUser.FaillockFailures = intPtr(0); return n }},
		{name: "shadow.new left over", id: "salt-user", status: "warn", message: master + ": /etc/shadow.new left over",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { n[0].SaltUser.ShadowNewLeftover = true; return n }},
		{name: "shadow too open", id: "salt-user", status: "warn", message: master + ": /etc/shadow mode 0644 is wider than 0640",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { n[0].SaltUser.Files[1].Mode = "0644"; return n }},
		{name: "shadow closed", id: "salt-user", status: "ok",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { n[0].SaltUser.Files[1].Mode = "0000"; return n }},
		{name: "passwd not world-readable", id: "salt-user", status: "warn", message: master + ": /etc/passwd mode 0600 is not world-readable",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { n[0].SaltUser.Files[0].Mode = "0600"; return n }},
		{name: "group not world-readable", id: "salt-user", status: "warn", message: master + ": /etc/group mode 0640 is not world-readable",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { n[0].SaltUser.Files[2].Mode = "0640"; return n }},
		{name: "missing file mode", id: "salt-user", status: "ok",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0].SaltUser.Files = []FileDiagnostics{{Path: "/etc/shadow", Error: "no such file"}}
				return n
			}},

		{name: "no long-running jobs", id: "salt-jobs", status: "ok", message: "no long-running salt jobs",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Jobs.MinionJobs = []SaltJobDiagnostics{{Jid: "20261118101500123456", AgeSeconds: int64Ptr(3600)}, {Jid: "not-a-jid"}}
				return n
			}},
		{name: "long-running minion job", id: "salt-jobs", status: "warn", nodes: []string{minion},
			message: minion + ": minion job 20261118101500123456 running for 2h3m",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Jobs.MinionJobs = []SaltJobDiagnostics{{Jid: "20261118101500123456", AgeSeconds: int64Ptr(7380)}}
				return n
			}},
		{name: "job just over an hour", id: "salt-jobs", status: "warn", message: "running for 1h0m",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Jobs.MinionJobs = []SaltJobDiagnostics{{Jid: "20261118101500123456", AgeSeconds: int64Ptr(3601)}}
				return n
			}},
		{name: "long-running master job", id: "salt-jobs", status: "warn", nodes: []string{master},
			message: master + ": master job 20261118101500123456 running for 25h0m",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0].Jobs.MasterJobs = []SaltJobDiagnostics{{Jid: "20261118101500123456", AgeSeconds: int64Ptr(90000)}}
				return n
			}},
		{name: "many long-running jobs are one finding", id: "salt-jobs", status: "warn",
			message: minion + ": 7 minion jobs running for over 1h0m: 20261118000001000000 (3h0m), 20261118000002000000 (3h0m), " +
				"20261118000003000000 (3h0m), 20261118000004000000 (3h0m), 20261118000005000000 (3h0m) and 2 more",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				for i := 1; i <= 7; i++ {
					n[1].Jobs.MinionJobs = append(n[1].Jobs.MinionJobs, SaltJobDiagnostics{Jid: fmt.Sprintf("2026111800000%d000000", i), AgeSeconds: int64Ptr(10800)})
				}
				return n
			}},
		{name: "minion and master jobs are separate findings", id: "salt-jobs", status: "warn", nodes: []string{master},
			message: master + ": minion job 20261118101500123456 running for 2h0m; " + master + ": master job 20261118111500123456 running for 1h30m",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0].Jobs.MinionJobs = []SaltJobDiagnostics{{Jid: "20261118101500123456", AgeSeconds: int64Ptr(7200)}}
				n[0].Jobs.MasterJobs = []SaltJobDiagnostics{{Jid: "20261118111500123456", AgeSeconds: int64Ptr(5400)}}
				return n
			}},
		{name: "too many minions for the default worker threads", id: "salt-jobs", status: "warn", nodes: []string{master},
			message: master + ": worker_threads is 5 for 126 accepted minions; the master may time out under load",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0].Master.Minions = acceptedMinions(126)
				return n
			}},
		{name: "minions at the limit of the default worker threads", id: "salt-jobs", status: "ok",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { n[0].Master.Minions = acceptedMinions(125); return n }},
		{name: "pending keys are not counted", id: "salt-jobs", status: "ok",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0].Master.Minions = acceptedMinions(125)
				for i := 0; i < 20; i++ {
					n[0].Master.Minions = append(n[0].Master.Minions, MasterMinionDiagnostics{Id: fmt.Sprintf("pending%d", i), KeyState: "pending"})
				}
				return n
			}},
		{name: "worker threads raised for the minions", id: "salt-jobs", status: "ok",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0].Master.Minions, n[0].Jobs.WorkerThreads = acceptedMinions(243), intPtr(10)
				return n
			}},
		{name: "too many minions for the configured worker threads", id: "salt-jobs", status: "warn", message: "worker_threads is 10 for 251 accepted minions",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0].Master.Minions, n[0].Jobs.WorkerThreads = acceptedMinions(251), intPtr(10)
				return n
			}},
		{name: "master without job data keeps the default out of it", id: "salt-jobs", status: "ok",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0].Master.Minions, n[0].Jobs = acceptedMinions(300), nil
				return n
			}},
		{name: "no job data", id: "salt-jobs", status: "skipped", message: "no job data",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { n[0].Jobs, n[1].Jobs = nil, nil; return n }},

		{name: "clocks agree", id: "clock", status: "ok", message: "clocks are NTP synchronized and agree"},
		{name: "NTP disabled", id: "clock", status: "warn", message: minion + ": NTP is disabled", nodes: []string{minion},
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Time.NtpEnabled, n[1].Time.NtpSynchronized = boolPtr(false), boolPtr(false)
				return n
			}},
		{name: "clock not synchronized", id: "clock", status: "warn", message: master + ": clock is not NTP synchronized", nodes: []string{master},
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { n[0].Time.NtpSynchronized = boolPtr(false); return n }},
		{name: "clock not synchronized and NTP state unknown", id: "clock", status: "warn", message: master + ": clock is not NTP synchronized",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0].Time.NtpEnabled, n[0].Time.NtpSynchronized = nil, boolPtr(false)
				return n
			}},
		{name: "unknown NTP state", id: "clock", status: "ok",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0].Time.NtpEnabled, n[0].Time.NtpSynchronized = nil, nil
				return n
			}},
		{name: "clock six minutes ahead", id: "clock", status: "fail", nodes: []string{"10.0.0.3"},
			message: "10.0.0.3: clock is 6m0s ahead of the median of the nodes; Kerberos rejects skew over 5 minutes",
			mutate:  thirdNode("2026-11-18T10:06:00Z")},
		{name: "clock six minutes behind", id: "clock", status: "fail", message: "10.0.0.3: clock is 6m0s behind the median of the nodes; Kerberos rejects skew over 5 minutes",
			mutate: thirdNode("2026-11-18T09:54:00Z")},
		{name: "clock five minutes ahead", id: "clock", status: "warn", message: "10.0.0.3: clock is 5m0s ahead of the median of the nodes",
			mutate: thirdNode("2026-11-18T10:05:00Z")},
		{name: "clock two minutes and ten seconds ahead", id: "clock", status: "warn", nodes: []string{"10.0.0.3"},
			message: "10.0.0.3: clock is 2m10s ahead of the median of the nodes",
			mutate:  thirdNode("2026-11-18T10:02:10Z")},
		{name: "clock two minutes ahead", id: "clock", status: "ok", mutate: thirdNode("2026-11-18T10:02:00Z")},
		{name: "clock ahead by the delay of the fan-out", id: "clock", status: "ok",
			mutate: delayedThirdNode("2026-11-18T10:02:30Z", 150*time.Second)},
		{name: "clock ahead by more than the delay of the fan-out", id: "clock", status: "warn", nodes: []string{"10.0.0.3"},
			message: "10.0.0.3: clock is 2m10s ahead of the median of the nodes",
			mutate:  delayedThirdNode("2026-11-18T10:03:20Z", 70*time.Second)},
		{name: "clock ahead without a delay of the fan-out", id: "clock", status: "warn", nodes: []string{"10.0.0.3"},
			message: "10.0.0.3: clock is 2m30s ahead of the median of the nodes",
			mutate:  delayedThirdNode("2026-11-18T10:02:30Z", 0)},
		{name: "delay of the fan-out counts in whole seconds", id: "clock", status: "ok",
			mutate: delayedThirdNode("2026-11-18T10:02:30Z", 150*time.Second+900*time.Millisecond)},
		{name: "two nodes 400 seconds apart", id: "clock", status: "fail", nodes: []string{master},
			message: master + ": clock is 6m40s behind the median of the nodes; Kerberos rejects skew over 5 minutes",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0].Time.Now, n[1].Time.Now = "2026-11-18T10:00:00Z", "2026-11-18T10:06:40Z"
				return n
			}},
		{name: "two nodes 200 seconds apart", id: "clock", status: "warn", nodes: []string{minion},
			message: minion + ": clock is 3m20s behind the median of the nodes",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0].Time.Now, n[1].Time.Now = "2026-11-18T10:03:20Z", "2026-11-18T10:00:00Z"
				return n
			}},
		{name: "skew is only compared between parsable times", id: "clock", status: "ok",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0].Time.Now, n[1].Time.Now = "2026-11-18T10:00:00Z", "yesterday"
				return n
			}},
		{name: "an unanswered node is not compared", id: "clock", status: "ok",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1] = NodeDiagnostics{Address: minion, StatusCode: 500}
				return n
			}},
		{name: "no time", id: "clock", status: "skipped", message: "no time reported",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { n[0].Time, n[1].Time = nil, nil; return n }},

		{name: "resources fine", id: "resources", status: "ok"},
		{name: "root space low", id: "resources", status: "warn", message: minion + ": / space 5.0% left", nodes: []string{minion},
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Resources.Disk.Root.AvailableBytes = uint64Ptr(50)
				return n
			}},
		{name: "root space at the limit", id: "resources", status: "ok",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Resources.Disk.Root.AvailableBytes = uint64Ptr(100)
				return n
			}},
		{name: "root space exhausted", id: "resources", status: "fail", message: minion + ": / space 1.0% left",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Resources.Disk.Root.AvailableBytes = uint64Ptr(10)
				return n
			}},
		{name: "root inodes low", id: "resources", status: "warn", message: minion + ": / inodes 9.0% left",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Resources.Disk.Root.FreeInodes = uint64Ptr(90)
				return n
			}},
		{name: "root inodes exhausted", id: "resources", status: "fail", message: minion + ": / inodes 0.0% left",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Resources.Disk.Root.FreeInodes = uint64Ptr(0)
				return n
			}},
		{name: "filesystem without inodes", id: "resources", status: "ok",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Resources.Disk.Root.TotalInodes, n[1].Resources.Disk.Root.FreeInodes = nil, nil
				return n
			}},
		{name: "mount space low", id: "resources", status: "warn", message: minion + ": /var space 8.0% left",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Resources.Disk.Mounts[0].AvailableBytes = uint64Ptr(80)
				return n
			}},
		{name: "mount inodes exhausted", id: "resources", status: "fail", message: minion + ": /var inodes 1.0% left",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Resources.Disk.Mounts[0].TotalInodes, n[1].Resources.Disk.Mounts[0].FreeInodes = uint64Ptr(1000), uint64Ptr(10)
				return n
			}},
		{name: "logical volume space low", id: "resources", status: "warn", message: minion + ": /srv space 4.0% left",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Resources.Disk.Lvm = &LvmDiagnostics{LogicalVolumes: []LogicalVolumeDiagnostics{
					{Name: "srv", MountPoints: []string{"/srv"}, FsTotalBytes: uint64Ptr(1000), FsAvailableBytes: uint64Ptr(40)}}}
				return n
			}},
		{name: "logical volume inodes low", id: "resources", status: "warn", message: minion + ": /srv inodes 4.0% left",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Resources.Disk.Lvm = &LvmDiagnostics{LogicalVolumes: []LogicalVolumeDiagnostics{
					{Name: "srv", MountPoints: []string{"/srv"}, FsTotalBytes: uint64Ptr(1000), FsAvailableBytes: uint64Ptr(900),
						FsTotalInodes: uint64Ptr(1000), FsFreeInodes: uint64Ptr(40)}}}
				return n
			}},
		{name: "logical volume of a mount is reported once", id: "resources", status: "warn", message: minion + ": /var space 8.0% left",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[1].Resources.Disk.Mounts[0].AvailableBytes = uint64Ptr(80)
				n[1].Resources.Disk.Lvm = &LvmDiagnostics{LogicalVolumes: []LogicalVolumeDiagnostics{
					{Name: "var", MountPoints: []string{"/var"}, FsTotalBytes: uint64Ptr(1000), FsAvailableBytes: uint64Ptr(80)}}}
				return n
			}},
		{name: "oom kills", id: "resources", status: "warn", message: master + ": 2 processes killed by the OOM killer since boot",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { n[0].Resources.Memory.OomKills = uint64Ptr(2); return n }},
		{name: "unknown oom kills", id: "resources", status: "ok",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { n[0].Resources.Memory.OomKills = nil; return n }},
		{name: "high load", id: "resources", status: "warn", message: master + ": load5 per CPU is 2.50",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0].Resources.Load.Load5PerCpu = float64Ptr(2.5)
				return n
			}},
		{name: "load of two per CPU", id: "resources", status: "ok",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { n[0].Resources.Load.Load5PerCpu = float64Ptr(2); return n }},
		{name: "failure listed before warning", id: "resources", status: "fail", message: minion + ": / space 1.0% left; " + master + ": 1 processes killed",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics {
				n[0].Resources.Memory.OomKills = uint64Ptr(1)
				n[1].Resources.Disk.Root.AvailableBytes = uint64Ptr(10)
				return n
			}},
		{name: "no resources", id: "resources", status: "skipped",
			mutate: func(n []NodeDiagnostics) []NodeDiagnostics { n[0].Resources, n[1].Resources = nil, nil; return n }},
	}

	for _, c := range cases {
		nodes := healthyCluster()
		if c.mutate != nil {
			nodes = c.mutate(nodes)
		}
		var found *DiagnosticsCheck
		checks := computeDiagnosticsChecks(nodes, c.units)
		for i := range checks {
			if checks[i].Id == c.id {
				found = &checks[i]
			}
		}
		switch {
		case found == nil:
			t.Errorf("%s/%s: check not found in %+v", c.id, c.name, checks)
		case found.Status != c.status:
			t.Errorf("%s/%s: expected status %s, got %+v", c.id, c.name, c.status, *found)
		case !strings.Contains(found.Message, c.message):
			t.Errorf("%s/%s: expected message containing %q, got %+v", c.id, c.name, c.message, *found)
		case c.nodes != nil && !reflect.DeepEqual(found.Nodes, c.nodes):
			t.Errorf("%s/%s: expected nodes %v, got %+v", c.id, c.name, c.nodes, *found)
		case c.status == "skipped" && found.Message == "":
			t.Errorf("%s/%s: a skipped check needs a reason", c.id, c.name)
		}
	}
}

func sign(i int) int { return min(1, max(-1, i)) }

func TestCompareSaltVersions(t *testing.T) {
	cases := []struct {
		a, b   string
		result int
		ok     bool
	}{
		{"3006.10", "3006.9", 1, true},
		{"3006.9", "3006.10", -1, true},
		{"3006.9", "3001.8", 1, true},
		{"3006.10", "3006.10", 0, true},
		{"3006", "3006.0", 0, true},
		{"3006.1", "3006", 1, true},
		{"3007.0rc1", "3006.10", 1, true},
		{"3006.10", "", 0, false},
		{"latest", "3006.10", 0, false},
	}
	for _, c := range cases {
		result, ok := compareSaltVersions(c.a, c.b)
		if ok != c.ok || (ok && sign(result) != c.result) {
			t.Errorf("compareSaltVersions(%q, %q) = %d, %t; expected %d, %t", c.a, c.b, result, ok, c.result, c.ok)
		}
	}
}

func TestDiagnosticsDistributeHandlerReturnsChecks(t *testing.T) {
	healthy := healthyCluster()[0]
	healthy.Resources.Disk.Root.AvailableBytes = uint64Ptr(10)
	body, err := json.Marshal(healthy)
	if err != nil {
		t.Fatal(err)
	}
	current := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(body) }))
	defer current.Close()
	older := httptest.NewServer(http.NotFoundHandler())
	defer older.Close()

	targets, _ := json.Marshal(map[string]any{"targets": []string{current.Listener.Addr().String(), older.Listener.Addr().String()}, "additionalUnits": []string{"nginx"}})
	req := httptest.NewRequest("POST", "/saltboot/diagnostics/distribute", bytes.NewBuffer(targets))
	w := httptest.NewRecorder()
	DiagnosticsDistributeHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body)
	}
	var response DiagnosticsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Nodes) != 2 || len(response.Checks) != 17 {
		t.Fatalf("expected 2 nodes and 17 checks: %s", w.Body)
	}
	statuses := map[string]DiagnosticsCheck{}
	for _, check := range response.Checks {
		statuses[check.Id] = check
	}
	reachable, resources := statuses["node-reachable"], statuses["resources"]
	if reachable.Status != "warn" || !strings.Contains(reachable.Message, older.Listener.Addr().String()+": 404") ||
		len(reachable.Nodes) != 1 || reachable.Nodes[0] != older.Listener.Addr().String() {
		t.Errorf("unexpected node-reachable check: %+v", reachable)
	}
	if resources.Status != "fail" || !strings.Contains(resources.Message, current.Listener.Addr().String()+": / space 1.0% left") {
		t.Errorf("unexpected resources check: %+v", resources)
	}
	if !strings.Contains(w.Body.String(), `"checks":[{"id":"node-reachable","status":"warn"`) {
		t.Errorf("expected the checks in the json: %s", w.Body)
	}
}

func TestDiagnosticsCheckEntriesUseTheIdOfTheirCheck(t *testing.T) {
	for _, nodes := range [][]NodeDiagnostics{nil, healthyCluster()} {
		for _, entry := range diagnosticsCheckEntries(nodes, nil) {
			if check := entry.run(); check.Id != entry.id {
				t.Errorf("entry %s runs the check %s", entry.id, check.Id)
			}
		}
	}
}

func TestRunDiagnosticsChecksTurnsAPanicIntoAnErrorCheck(t *testing.T) {
	entries := diagnosticsCheckEntries(healthyCluster(), nil)
	entries[3].run = func() DiagnosticsCheck {
		var node *NodeDiagnostics
		return DiagnosticsCheck{Id: "salt-units", Status: node.Address}
	}
	var logged bytes.Buffer
	log.SetOutput(&logged)
	defer log.SetOutput(os.Stderr)

	checks := runDiagnosticsChecks(entries)

	if len(checks) != 17 {
		t.Fatalf("expected an entry for every check, got %+v", checks)
	}
	broken := checkById(t, checks, "salt-units")
	if broken.Status != diagnosticsCheckError || !strings.HasPrefix(broken.Message, "check failed: ") {
		t.Errorf("unexpected check: %+v", broken)
	}
	for _, check := range checks {
		if check.Id != "salt-units" && check.Status == diagnosticsCheckError {
			t.Errorf("only salt-units should fail: %+v", check)
		}
	}
	if checkById(t, checks, "resources").Status != diagnosticsCheckOk || checks[3].Id != "salt-units" {
		t.Errorf("the other checks should be computed in order: %+v", checks)
	}
	if !strings.Contains(logged.String(), "[computeDiagnosticsChecks] [ERROR] check salt-units panicked") || !strings.Contains(logged.String(), "goroutine") {
		t.Errorf("expected the panic with its stack in the log: %s", logged.String())
	}
}

func TestDiagnosticsDistributeHandlerReturnsTheNodesWhenTheChecksPanic(t *testing.T) {
	original := computeChecks
	defer func() { computeChecks = original }()
	computeChecks = func([]NodeDiagnostics, []string) []DiagnosticsCheck { panic("boom") }
	body, err := json.Marshal(healthyCluster()[0])
	if err != nil {
		t.Fatal(err)
	}
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(body) }))
	defer node.Close()

	targets, _ := json.Marshal(map[string]any{"targets": []string{node.Listener.Addr().String()}})
	w := httptest.NewRecorder()
	DiagnosticsDistributeHandler(w, httptest.NewRequest("POST", "/saltboot/diagnostics/distribute", bytes.NewBuffer(targets)))

	var response DiagnosticsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK || len(response.Nodes) != 1 || response.Checks != nil || strings.Contains(w.Body.String(), `"checks"`) {
		t.Errorf("expected the node without checks, got %d: %s", w.Code, w.Body)
	}
}

func TestCollectDiagnosticsReportsPanickingProbesAndSetters(t *testing.T) {
	mockCommands(t, map[string]string{
		"/bin/systemctl show": "LoadState=loaded\nActiveState=active\nSubState=running\n",
		"timedatectl show":    "NTP=yes\nNTPSynchronized=yes\n",
	})
	baseDir := t.TempDir()
	probes := append(diagnosticsProbes(baseDir, DiagnosticsRequest{}),
		diagnosticsProbe{"explodingProbe", func() func(*NodeDiagnostics) { panic("probe boom") }},
		diagnosticsProbe{"explodingSetter", func() func(*NodeDiagnostics) {
			return func(d *NodeDiagnostics) {
				d.Version = "partly set"
				var missing *TimeDiagnostics
				_ = missing.Now
			}
		}},
		diagnosticsProbe{"nilSetter", func() func(*NodeDiagnostics) { return nil }})
	var logged bytes.Buffer
	log.SetOutput(&logged)
	defer log.SetOutput(os.Stderr)

	diagnostics := collectDiagnosticsWith(baseDir, requestWithLogLines(5), probes)

	failed := strings.Join(diagnostics.FailedProbes, "|")
	if len(diagnostics.FailedProbes) != 3 || !strings.Contains(failed, "explodingProbe: probe boom") ||
		!strings.Contains(failed, "explodingSetter: runtime error: invalid memory address") || !strings.Contains(failed, "nilSetter: ") {
		t.Errorf("unexpected failed probes: %v", diagnostics.FailedProbes)
	}
	if len(diagnostics.TimedOutProbes) != 0 || len(diagnostics.Units) == 0 || diagnostics.Time == nil || diagnostics.Minion == nil ||
		diagnostics.Resources == nil || len(diagnostics.Logs) != 2 {
		t.Errorf("the other probes should still answer: %+v", diagnostics)
	}
	if !strings.Contains(logged.String(), "probe explodingProbe panicked") || !strings.Contains(logged.String(), "goroutine") {
		t.Errorf("expected the panic with its stack in the log: %s", logged.String())
	}
	check := checkTimedOutProbes([]NodeDiagnostics{diagnostics})
	if check.Status != diagnosticsCheckWarn || !strings.Contains(check.Message, "probes failed: ") {
		t.Errorf("unexpected check: %+v", check)
	}
}

func TestCollectDiagnosticsSurvivesAPanickingRealProbe(t *testing.T) {
	mockCommands(t, map[string]string{"/bin/systemctl show": "LoadState=loaded\nActiveState=active\nSubState=running\n"})
	mocked := timedCommandExecutor
	timedCommandExecutor = func(timeout time.Duration, executable string, args ...string) ([]byte, error) {
		if executable == "timedatectl" {
			panic("no timedatectl")
		}
		return mocked(timeout, executable, args...)
	}

	diagnostics := collectDiagnostics(t.TempDir(), requestWithLogLines(0))

	if len(diagnostics.FailedProbes) != 1 || diagnostics.FailedProbes[0] != "time: no timedatectl" || diagnostics.Time != nil || len(diagnostics.Units) == 0 {
		t.Errorf("unexpected diagnostics: %+v", diagnostics)
	}
}

func TestCollectDiagnosticsReportsAPanicInAnInnerGoroutine(t *testing.T) {
	mockCommands(t, map[string]string{
		"/bin/systemctl show": "LoadState=loaded\nActiveState=active\nSubState=running\n",
		"timedatectl show":    "NTP=yes\nNTPSynchronized=yes\n",
		"hostname":            "node1\n",
	})
	timed := timedCommandExecutor
	timedCommandExecutor = func(timeout time.Duration, executable string, args ...string) ([]byte, error) {
		if executable == "hostname" && len(args) == 1 && args[0] == "-f" {
			panic("hostname -f boom")
		}
		return timed(timeout, executable, args...)
	}
	originalDial := dialTimeout
	defer func() { dialTimeout = originalDial }()
	dialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) { panic("dial boom") }
	baseDir := t.TempDir()
	writeTestFile(t, baseDir, "/etc/salt/minion.d/master.conf", "master:\n- 10.0.0.1\n")
	var logged bytes.Buffer
	log.SetOutput(&logged)
	defer log.SetOutput(os.Stderr)

	diagnostics := collectDiagnostics(baseDir, requestWithLogLines(0))

	if strings.Join(diagnostics.FailedProbes, "|") != "host: hostname -f boom|minion: dial boom" {
		t.Errorf("unexpected failed probes: %v", diagnostics.FailedProbes)
	}
	if diagnostics.Host != nil || len(diagnostics.Units) == 0 || diagnostics.Time == nil || diagnostics.Resources == nil {
		t.Errorf("the other probes should still answer: %+v", diagnostics)
	}
	if !strings.Contains(logged.String(), "goroutine of a probe panicked: dial boom") {
		t.Errorf("expected the inner panic in the log: %s", logged.String())
	}
}

func TestCollectDiagnosticsReportsAPanicInTheLogsProbe(t *testing.T) {
	mockCommands(t, map[string]string{
		"/bin/systemctl show": "LoadState=loaded\nActiveState=active\nSubState=running\n",
		"timedatectl show":    "NTP=yes\nNTPSynchronized=yes\n",
	})
	original := readLogs
	defer func() { readLogs = original }()
	readLogs = func(string, int) []LogDiagnostics { panic("logs boom") }

	diagnostics := collectDiagnostics(t.TempDir(), requestWithLogLines(5))

	if strings.Join(diagnostics.FailedProbes, "|") != "logs: logs boom" || diagnostics.Logs != nil || len(diagnostics.Units) == 0 || diagnostics.Time == nil {
		t.Errorf("unexpected diagnostics: %+v", diagnostics)
	}
}

func TestCollectDiagnosticsDeadlineCoversReadingTheLogs(t *testing.T) {
	original := readLogs
	release := make(chan struct{})
	defer func() { readLogs = original; close(release) }()
	readLogs = func(string, int) []LogDiagnostics {
		time.Sleep(1 * time.Second)
		return nil
	}
	probes := []diagnosticsProbe{{"jobs", func() func(*NodeDiagnostics) { <-release; return func(*NodeDiagnostics) {} }}}
	request := requestWithLogLines(5)
	request.ProbeDeadline = "1200ms"

	start := time.Now()
	diagnostics := collectDiagnosticsWith(t.TempDir(), request, probes)

	// the deadline is the whole budget, so the 1s of the logs leaves 200ms, not 1200ms, to the probes:
	// the call takes about 1.2s, where counting the deadline from the end of the logs would take about 2.2s
	if elapsed := time.Since(start); elapsed >= 1800*time.Millisecond || strings.Join(diagnostics.TimedOutProbes, ",") != "jobs" {
		t.Errorf("expected the jobs probe to time out after about 1200ms, got %s and %+v", elapsed, diagnostics)
	}
}

func TestCheckAdditionalUnitsGroupsTheSameProblem(t *testing.T) {
	var nodes []NodeDiagnostics
	for i := 1; i <= 9; i++ {
		nodes = append(nodes, NodeDiagnostics{Address: fmt.Sprintf("10.0.0.%d:7071", i), Units: []UnitDiagnostics{
			{Name: "example-agent", LoadState: "loaded", ActiveState: "inactive", SubState: "dead"},
		}})
	}
	nodes[4].Units[0] = UnitDiagnostics{Name: "example-agent", LoadState: "not-found"}
	nodes[7].Units[0] = UnitDiagnostics{Name: "example-agent", LoadState: "loaded", ActiveState: "active"}

	check := checkAdditionalUnits(nodes, []string{"example-agent"})

	expected := "example-agent is inactive (dead) on 7 nodes; 10.0.0.5:7071: example-agent not found"
	if check.Status != diagnosticsCheckWarn || check.Message != expected {
		t.Errorf("unexpected message: %s", check.Message)
	}
	if len(check.Nodes) != 8 || slices.Contains(check.Nodes, "10.0.0.8:7071") {
		t.Errorf("expected the 8 affected nodes, got %v", check.Nodes)
	}
}

func TestWithoutPorts(t *testing.T) {
	nodes := []NodeDiagnostics{
		{Address: "10.0.0.1:7071"}, {Address: "[fd00::1]:7071"}, {Address: "10.0.0.3"},
		{Address: "127.0.0.1:50001"}, {Address: "127.0.0.1:50002"},
	}

	var addresses []string
	for _, node := range withoutPorts(nodes) {
		addresses = append(addresses, node.Address)
	}

	// two targets on the same host keep their ports, so the checks can still tell them apart
	expected := "10.0.0.1,fd00::1,10.0.0.3,127.0.0.1:50001,127.0.0.1:50002"
	if strings.Join(addresses, ",") != expected {
		t.Errorf("expected %s, got %s", expected, strings.Join(addresses, ","))
	}
	if nodes[0].Address != "10.0.0.1:7071" {
		t.Errorf("the nodes of the response must keep their address, got %s", nodes[0].Address)
	}
}

// testTimeouts are the configured timeouts, cut to the configured probe deadline like a request without one.
func testTimeouts() probeTimeouts {
	return diagConfig().timeoutsWithin(diagConfig().ProbeDeadline)
}

func TestProbeTimeoutsAreCutToTheDeadline(t *testing.T) {
	setDiagnosticsConfig(t, func(c *DiagnosticsConfig) {
		c.CommandTimeout, c.LookupTimeout, c.SaltCallTimeout, c.LvmTimeout, c.DialTimeout =
			3*time.Second, 30*time.Second, 30*time.Second, 2*time.Second, 30*time.Second
	})

	timeouts := diagConfig().timeoutsWithin(5 * time.Second)

	expected := probeTimeouts{command: 3 * time.Second, lookup: 5 * time.Second, saltCall: 5 * time.Second, lvm: 2 * time.Second, dial: 5 * time.Second}
	if timeouts != expected {
		t.Errorf("expected %+v, got %+v", expected, timeouts)
	}
}

func TestProbesUseTheTimeoutsOfTheRequestedDeadline(t *testing.T) {
	setDiagnosticsConfig(t, func(c *DiagnosticsConfig) { c.LvmTimeout = 30 * time.Second })
	calls := mockLvm(t, map[string]string{"lvs": `{"report":[{"lv":[]}]}`, "vgs": `{"report":[{"vg":[]}]}`}, nil)

	for _, probe := range diagnosticsProbes(t.TempDir(), DiagnosticsRequest{ProbeDeadline: "4s"}) {
		if probe.name == "lvm" {
			probe.run()
		}
	}

	if len(*calls) != 2 {
		t.Fatalf("expected lvs and vgs to run, got %+v", *calls)
	}
	for _, call := range *calls {
		if call.timeout != 4*time.Second {
			t.Errorf("expected the 30s lvm timeout cut to the 4s deadline, got %s", call.timeout)
		}
	}
}

func TestProbeUnitAndTimeAreBoundByTheCommandTimeout(t *testing.T) {
	var timeouts []time.Duration
	originalTimed := timedCommandExecutor
	defer func() { timedCommandExecutor = originalTimed }()
	timedCommandExecutor = func(timeout time.Duration, executable string, args ...string) ([]byte, error) {
		timeouts = append(timeouts, timeout)
		return []byte("LoadState=loaded\nNTP=yes\n"), nil
	}

	probeUnit("salt-minion", probeTimeouts{command: 1500 * time.Millisecond})
	probeTime(probeTimeouts{command: 1500 * time.Millisecond})

	if len(timeouts) != 2 || timeouts[0] != 1500*time.Millisecond || timeouts[1] != 1500*time.Millisecond {
		t.Errorf("expected systemctl show and timedatectl to run with the command timeout, got %v", timeouts)
	}
}

// openssl passwd -6 -salt 0123456789abcdef 'S3cret-Pass', i.e. a hash salt-bootstrap did not write itself
const opensslSha512Hash = "$6$0123456789abcdef$I44neQULBgFIJmNilbcc0hDI363TU78.kWF50i3eaoK7oJqf7sYpFXiVuqx/7J55N4YZFe1U2j2FsAr3jiPMo."

func TestCheckShadowPassword(t *testing.T) {
	written, err := generatePasswordHash("expected-password")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, hash, password, expected, scheme string
	}{
		{"hash written by salt-bootstrap", written, "expected-password", "match", "sha512"},
		{"password changed", written, "changed-by-hand", "mismatch", "sha512"},
		{"hash written by openssl", opensslSha512Hash, "S3cret-Pass", "match", "sha512"},
		{"hash written by openssl, other password", opensslSha512Hash, "other", "mismatch", "sha512"},
		{"yescrypt of passwd on RHEL 9", "$y$j9T$abcdefghijklmnop$0123456789012345678901234567890123456789012", "x", "unverifiable", "yescrypt"},
		{"md5", "$1$abcdefgh$0123456789012345678901", "x", "unverifiable", "md5"},
		{"no password", "*", "x", "unverifiable", "none"},
		{"empty", "", "x", "unverifiable", "none"},
		{"des", "abJnggxhB/yWI", "x", "unverifiable", "des"},
	}
	for _, c := range cases {
		if actual := checkShadowPassword(c.hash, c.password); actual != c.expected {
			t.Errorf("%s: expected %s, got %s", c.name, c.expected, actual)
		}
		if scheme := passwordHashScheme(c.hash); scheme != c.scheme {
			t.Errorf("%s: expected the scheme %s, got %s", c.name, c.scheme, scheme)
		}
	}
}

func TestProbeSaltUserChecksTheRequestedPassword(t *testing.T) {
	mockCommands(t, map[string]string{})
	baseDir := t.TempDir()
	writeTestFile(t, baseDir, "/etc/shadow", "root:*:20000:0:99999:7:::\nsaltuser:!"+opensslSha512Hash+":20400:0:99999:7:::\n")

	for password, expected := range map[string]string{"S3cret-Pass": "match", "changed": "mismatch", "": ""} {
		user := probeSaltUser(baseDir, testTimeouts(), password)

		if user == nil || user.PasswordCheck != expected || user.PasswordHashScheme != "sha512" || !user.Locked {
			t.Errorf("password %q: expected %q on the locked account, got %+v", password, expected, user)
		}
		b, _ := json.Marshal(user)
		if password != "" && strings.Contains(string(b), password) || strings.Contains(string(b), "I44neQ") {
			t.Errorf("neither the password nor the hash may be part of the response: %s", b)
		}
	}
}

func TestDiagnosticsHandlerNeverEchoesTheSaltUserPassword(t *testing.T) {
	mockCommands(t, map[string]string{"/bin/systemctl show": "LoadState=loaded\nActiveState=active\n", "timedatectl show": "NTP=yes\n"})
	baseDir := t.TempDir()
	writeTestFile(t, baseDir, "/etc/shadow", "saltuser:"+opensslSha512Hash+":20400:0:99999:7:::\n")
	var logged bytes.Buffer
	originalOutput := log.Writer()
	log.SetOutput(&logged)
	defer log.SetOutput(originalOutput)

	req := httptest.NewRequest("POST", "/saltboot/diagnostics", bytes.NewBufferString(`{"logLines": 0, "saltUserPassword": "S3cret-Pass"}`))
	req.Header.Set("salt-minion-base-dir", baseDir)
	w := httptest.NewRecorder()
	DiagnosticsHandler(w, req)

	if !strings.Contains(w.Body.String(), `"passwordCheck":"match"`) {
		t.Errorf("expected a matching password, got %s", w.Body)
	}
	if strings.Contains(w.Body.String(), "S3cret-Pass") || strings.Contains(logged.String(), "S3cret-Pass") {
		t.Errorf("the password must appear neither in the response nor in the log")
	}
}

func TestCrashLoopThresholdsAreConfigurable(t *testing.T) {
	unit := UnitDiagnostics{Name: "salt-minion", LoadState: "loaded", ActiveState: "active", NRestarts: intPtr(33),
		Process: &ProcessDiagnostics{UptimeSeconds: int64Ptr(90)}}
	if _, found := unitProblem(unit); found {
		t.Errorf("a process up 90s is not crash-looping with the default 1m")
	}

	setDiagnosticsConfig(t, func(c *DiagnosticsConfig) { c.CrashLoopUptime = 5 * time.Minute })
	if problem, found := unitProblem(unit); !found || problem != "salt-minion is crash-looping: restarted 33 times, the current process is up 90s" {
		t.Errorf("expected a crash loop with crashLoopUptime 5m, got %q", problem)
	}

	setDiagnosticsConfig(t, func(c *DiagnosticsConfig) { c.CrashLoopRestarts = 50 })
	if _, found := unitProblem(unit); found {
		t.Errorf("33 restarts are below crashLoopRestarts 50")
	}

	unit.Process = nil
	setDiagnosticsConfig(t, func(c *DiagnosticsConfig) { c.CrashLoopRestarts = 1 })
	if _, found := unitProblem(unit); found {
		t.Errorf("without the process uptime a crash loop cannot be told apart from old restarts")
	}
}
