package saltboot

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hortonworks/salt-bootstrap/saltboot/model"
	"gopkg.in/yaml.v2"
)

func TestDistributeActionImplWithoutMaster(t *testing.T) {
	distributeRequest := func(clients []string, endpoint string, user string, pass string, requestBody RequestBody) <-chan model.Response {
		c := make(chan model.Response, len(clients))
		for _, client := range clients {
			c <- model.Response{StatusCode: 200, ErrorText: "", Address: client}
		}
		close(c)
		return c
	}
	minions := make([]SaltMinion, 0)
	minions = append(minions, SaltMinion{Address: "address"})
	request := SaltActionRequest{
		Minions: minions,
	}

	resp := distributeActionImpl(distributeRequest, request, "user", "pass", RequestBody{})

	if len(resp) != len(minions) {
		t.Errorf("size not match %d == %d", len(minions), len(resp))
	} else {
		for i, r := range resp {
			if r.Address != minions[i].Address {
				t.Errorf("address not match %s == %s", minions[i].Address, r.Address)
			}
		}
	}
}

func TestDistributeActionImplMaster(t *testing.T) {
	distributeRequest := func(clients []string, endpoint string, user string, pass string, requestBody RequestBody) <-chan model.Response {
		c := make(chan model.Response, len(clients))
		for _, client := range clients {
			c <- model.Response{StatusCode: 200, ErrorText: "", Address: client}
		}
		close(c)
		return c
	}
	request := SaltActionRequest{
		Master: SaltMaster{Address: "address"},
	}

	resp := distributeActionImpl(distributeRequest, request, "user", "pass", RequestBody{})

	if len(resp) != 1 {
		t.Errorf("size not match %d == %d", 1, len(resp))
	} else if resp[0].Address != request.Master.Address {
		t.Errorf("address not match %s == %s", request.Master.Address, resp[0].Address)
	}
}

func TestSaltMinionRunRequestHandler(t *testing.T) {
	watchCommands = true
	defer func() { watchCommands = false }()

	tempDirName, _ := os.MkdirTemp("", "saltminionruntest")
	defer os.RemoveAll(tempDirName)
	hostname := "testhostname.example.com"

	request := SaltActionRequest{
		Master: SaltMaster{Address: "address"},
		Minions: []SaltMinion{{
			Address:   "address",
			HostGroup: "group",
			Server:    "server",
			Hostname:  &hostname,
			Roles:     []string{"role1", "role2"},
		}},
	}
	body := bytes.NewBuffer(make([]byte, 0))
	encoder := json.NewEncoder(body)
	encoder.Encode(&request)

	req := httptest.NewRequest("POST", "/?index=0", body)
	req.Header.Set("salt-minion-base-dir", tempDirName)
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		defer close(done)
		SaltMinionRunRequestHandler(w, req)
	}()

	checkExecutedCommands([]string{
		"hostname -d",
		"hostname testhostname.example.com",
		"grep SUSE /etc/issue",
		"grep sles12 /etc/issue",
		"ps aux",
		"/bin/systemctl start salt-minion",
		"/bin/systemctl enable salt-minion",
	}, t)
	<-done

	if _, err := os.Stat(tempDirName + "/etc/salt/minion.d"); os.IsNotExist(err) {
		t.Errorf("missing minion dir %s", tempDirName+"/etc/salt/minion.d")
	}

	content, _ := os.ReadFile(tempDirName + "/etc/salt/minion.d/master.conf")
	var masters map[string][]string
	yaml.Unmarshal(content, &masters)
	expectedMaster := map[string][]string{"master": {"server"}}
	if masters["master"][0] != expectedMaster["master"][0] {
		t.Errorf("master config not match %s == %s", expectedMaster, string(content))
	}

	grainYaml, _ := os.ReadFile(tempDirName + "/etc/salt/grains")
	if err := yaml.Unmarshal(grainYaml, &GrainConfig{}); err != nil {
		t.Errorf("couldn't unmarshall grain yaml: %s", err)
	}

	idContent, _ := os.ReadFile(tempDirName + "/etc/salt/minion.d/minion_id.conf")
	var idConf map[string]string
	yaml.Unmarshal(idContent, &idConf)
	if idConf["id"] != "testhostname.example.com" {
		t.Errorf("minion id not pinned, expected testhostname.example.com, got %q (raw: %s)", idConf["id"], string(idContent))
	}
}

// drainCommands collects every command pushed onto the watch channel until no
// new command arrives within timeout, then returns them. It lets a test assert
// over the full command set without deadlocking when an expected command is
// (incorrectly) never emitted.
func drainCommands(timeout time.Duration) []string {
	var cmds []string
	for {
		select {
		case c := <-commands:
			cmds = append(cmds, c)
		case <-time.After(timeout):
			return cmds
		}
	}
}

func containsCommand(cmds []string, target string) bool {
	for _, c := range cmds {
		if c == target {
			return true
		}
	}
	return false
}

func TestSaltMinionRunRequestHandlerRestartsOnIdDrift(t *testing.T) {
	watchCommands = true
	defer func() { watchCommands = false }()

	// Report salt-minion as already running so the launch decision is observable:
	// a no-op LaunchService emits no systemctl command, a restart emits one.
	originalExec := commandExecutor
	commandExecutor = func(executable string, args ...string) ([]byte, error) {
		command := executable
		if len(args) != 0 {
			command += " " + strings.Join(args, " ")
		}
		if watchCommands {
			commands <- command
		}
		if executable == "ps" {
			return []byte("salt-minion is running"), nil
		}
		return make([]byte, 0), nil
	}
	defer func() { commandExecutor = originalExec }()

	tempDirName, _ := os.MkdirTemp("", "saltminiondrifttest")
	defer os.RemoveAll(tempDirName)
	// A minion already cached a stale (cloud-default) id before saltboot ran.
	os.MkdirAll(tempDirName+"/etc/salt", 0755)
	os.WriteFile(tempDirName+"/etc/salt/minion_id", []byte("stale.internal.cloudapp.net"), 0644)

	hostname := "testhostname.example.com"
	request := SaltActionRequest{
		Master: SaltMaster{Address: "address"},
		Minions: []SaltMinion{{
			Address:   "address",
			HostGroup: "group",
			Server:    "server",
			Hostname:  &hostname,
			Roles:     []string{"role1", "role2"},
		}},
	}
	body := bytes.NewBuffer(make([]byte, 0))
	json.NewEncoder(body).Encode(&request)

	req := httptest.NewRequest("POST", "/?index=0", body)
	req.Header.Set("salt-minion-base-dir", tempDirName)
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		defer close(done)
		SaltMinionRunRequestHandler(w, req)
	}()

	executed := drainCommands(time.Second)
	<-done

	if !containsCommand(executed, "/bin/systemctl restart salt-minion") {
		t.Errorf("expected salt-minion restart on id drift, got commands: %v", executed)
	}
	if containsCommand(executed, "/bin/systemctl start salt-minion") {
		t.Errorf("expected restart (not start) on id drift, got commands: %v", executed)
	}
}

func TestSaltMinionRunRequestHandlerConvergesIdCacheAfterServiceSuccess(t *testing.T) {
	cases := []struct {
		name           string
		running        bool
		failCommand    string
		failGrains     bool
		firstStatus    int
		serviceActions [3]int
	}{
		{name: "successful restart", running: true, firstStatus: http.StatusOK, serviceActions: [3]int{1, 1, 1}},
		{name: "grains write failure", running: true, failGrains: true, firstStatus: http.StatusInternalServerError, serviceActions: [3]int{0, 1, 1}},
		{name: "restart failure", running: true, failCommand: "restart salt-minion", firstStatus: http.StatusInternalServerError, serviceActions: [3]int{1, 2, 2}},
		{name: "enable failure", running: true, failCommand: "enable salt-minion", firstStatus: http.StatusInternalServerError, serviceActions: [3]int{1, 2, 2}},
		{name: "start failure", failCommand: "start salt-minion", firstStatus: http.StatusInternalServerError, serviceActions: [3]int{1, 2, 2}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			baseDir := t.TempDir()
			if err := os.MkdirAll(baseDir+"/etc/salt", 0755); err != nil {
				t.Fatal(err)
			}
			const staleId = "stale.internal.cloudapp.net\n"
			cachePath := baseDir + "/etc/salt/minion_id"
			if err := os.WriteFile(cachePath, []byte(staleId), 0644); err != nil {
				t.Fatal(err)
			}
			if tc.failGrains {
				if err := os.Mkdir(baseDir+"/etc/salt/grains", 0755); err != nil {
					t.Fatal(err)
				}
			}

			originalExec := commandExecutor
			defer func() { commandExecutor = originalExec }()
			running := tc.running
			failed := false
			var serviceActions []string
			commandExecutor = func(executable string, args ...string) ([]byte, error) {
				if executable == "ps" && running {
					return []byte("salt-minion is running"), nil
				}
				if executable == "/bin/systemctl" {
					command := strings.Join(args, " ")
					if command == "restart salt-minion" || command == "start salt-minion" {
						serviceActions = append(serviceActions, command)
					}
					if command == tc.failCommand && !failed {
						failed = true
						return nil, errors.New("injected service failure")
					}
					if command == "restart salt-minion" || command == "start salt-minion" {
						running = true
					}
				}
				return nil, nil
			}

			hostname := "host-1"
			request := SaltActionRequest{
				Master:  SaltMaster{Address: "master", Domain: "example.com"},
				Minions: []SaltMinion{{Address: "10.0.0.1", Hostname: &hostname, Roles: []string{"role"}}},
			}
			body, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			for attempt := 0; attempt < 3; attempt++ {
				req := httptest.NewRequest("POST", "/?index=0", bytes.NewReader(body))
				req.Header.Set("salt-minion-base-dir", baseDir)
				w := httptest.NewRecorder()
				SaltMinionRunRequestHandler(w, req)

				expectedStatus := http.StatusOK
				expectedCache := "host-1.example.com\n"
				if attempt == 0 {
					expectedStatus = tc.firstStatus
					if expectedStatus != http.StatusOK {
						expectedCache = staleId
					}
				}
				if w.Code != expectedStatus {
					t.Errorf("attempt %d: expected HTTP %d, got %d: %s", attempt+1, expectedStatus, w.Code, w.Body.String())
				}
				cached, err := os.ReadFile(cachePath)
				if err != nil {
					t.Fatal(err)
				}
				if string(cached) != expectedCache {
					t.Errorf("attempt %d: expected cached id %q, got %q", attempt+1, expectedCache, cached)
				}
				if len(serviceActions) != tc.serviceActions[attempt] {
					t.Errorf("attempt %d: expected %d service actions, got %v", attempt+1, tc.serviceActions[attempt], serviceActions)
				}
				if attempt == 0 && tc.failGrains {
					if err := os.Remove(baseDir + "/etc/salt/grains"); err != nil {
						t.Fatal(err)
					}
				}
			}
			for _, action := range serviceActions {
				expectedAction := "start salt-minion"
				if tc.running {
					expectedAction = "restart salt-minion"
				}
				if action != expectedAction {
					t.Errorf("expected %q, got %q", expectedAction, action)
				}
			}
		})
	}
}

func TestSaltMinionStopRequestHandler(t *testing.T) {
	watchCommands = true
	defer func() { watchCommands = false }()

	request := SaltActionRequest{
		Master: SaltMaster{Address: "address"},
		Minions: []SaltMinion{{
			Address:   "address",
			HostGroup: "group",
			Server:    "server",
			Roles:     []string{"role1", "role2"},
		}},
	}
	body := bytes.NewBuffer(make([]byte, 0))
	encoder := json.NewEncoder(body)
	encoder.Encode(&request)

	req := httptest.NewRequest("GET", "/?index=0", body)
	w := httptest.NewRecorder()

	go SaltMinionStopRequestHandler(w, req)

	checkExecutedCommands([]string{
		"/bin/systemctl stop salt-minion",
		"/bin/systemctl disable salt-minion",
	}, t)
}

func TestSaltServerRunRequestHandler(t *testing.T) {
	watchCommands = true
	defer func() { watchCommands = false }()

	master := SaltMaster{}
	body := bytes.NewBuffer(make([]byte, 0))
	encoder := json.NewEncoder(body)
	encoder.Encode(&master)

	req := httptest.NewRequest("GET", "/?index=0", body)
	w := httptest.NewRecorder()

	go SaltServerRunRequestHandler(w, req)

	checkExecutedCommands([]string{
		"hostname -s",
		"hostname -d",
		"hostname ",
		"grep SUSE /etc/issue",
		"grep sles12 /etc/issue",
		"grep saltuser /etc/passwd",
		"grep Ubuntu /etc/issue",
		"grep Debian /etc/issue",
		"grep SUSE /etc/issue",
		"grep sles12 /etc/issue",
		"^adduser --no-create-home -G wheel -s /sbin/nologin --password \\$6\\$([a-zA-Z\\$0-9/.]+) saltuser",
		"ps aux",
		"/bin/systemctl start salt-master",
		"/bin/systemctl enable salt-master",
		"ps aux",
		"/bin/systemctl start salt-api",
		"/bin/systemctl enable salt-api",
	}, t)
}

func TestSaltServerStopRequestHandler(t *testing.T) {
	watchCommands = true
	defer func() { watchCommands = false }()

	req := httptest.NewRequest("GET", "/?index=0", nil)
	w := httptest.NewRecorder()

	go SaltServerStopRequestHandler(w, req)

	checkExecutedCommands([]string{
		"/bin/systemctl stop salt-master",
		"/bin/systemctl disable salt-master",
		"/bin/systemctl stop salt-api",
		"/bin/systemctl disable salt-api",
	}, t)
}

func TestWritePillar(t *testing.T) {
	tempDirName, _ := os.MkdirTemp("", "writepillartest")
	defer os.RemoveAll(tempDirName)

	json := make(map[string]interface{})
	json["key"] = "value"
	pillar := SaltPillar{
		Path: "/path/file",
		Json: json,
	}

	_, err := writePillarImpl(pillar, tempDirName)

	if err != nil {
		t.Errorf("error occurred during write %s", err)
	}

	expected := "#!json\n{\n\t\"key\": \"value\"\n}"
	content, _ := os.ReadFile(tempDirName + "/srv/pillar" + pillar.Path)
	if string(content) != expected {
		t.Errorf("yml content not match %s == %s", expected, string(content))
	}
}

func TestSaltMinionRunRequestHandlerRestartsWhenMasterRemoved(t *testing.T) {
	// RestartService checks the process list and then calls LaunchService, which checks it again,
	// so the restart path shows two "ps aux" calls.
	runSaltMinionRunRequestWithMasters(t, "master:\n- 10.0.0.1\n- 10.0.0.2\n- 10.0.0.3\n", []string{"10.0.0.1", "10.0.0.2"}, []string{
		"hostname -d",
		"hostname testhostname.example.com",
		"grep SUSE /etc/issue",
		"grep sles12 /etc/issue",
		"ps aux",
		"ps aux",
		"/bin/systemctl start salt-minion",
		"/bin/systemctl enable salt-minion",
	})
}

func TestSaltMinionRunRequestHandlerLaunchesWhenMasterListUnchanged(t *testing.T) {
	runSaltMinionRunRequestWithMasters(t, "master:\n- 10.0.0.1\n- 10.0.0.2\n", []string{"10.0.0.2", "10.0.0.1"}, []string{
		"hostname -d",
		"hostname testhostname.example.com",
		"grep SUSE /etc/issue",
		"grep sles12 /etc/issue",
		"ps aux",
		"/bin/systemctl start salt-minion",
		"/bin/systemctl enable salt-minion",
	})
}

func runSaltMinionRunRequestWithMasters(t *testing.T, originalMasterConf string, servers []string, expectedCommands []string) {
	watchCommands = true
	defer func() { watchCommands = false }()

	baseDir := t.TempDir()
	if err := os.MkdirAll(baseDir+"/etc/salt/minion.d", 0755); err != nil {
		t.Fatalf("failed to create minion dir: %s", err)
	}
	if err := os.WriteFile(baseDir+"/etc/salt/minion.d/master.conf", []byte(originalMasterConf), 0644); err != nil {
		t.Fatalf("failed to write master conf: %s", err)
	}
	hostname := "testhostname.example.com"
	request := SaltActionRequest{
		Master:  SaltMaster{Address: servers[0]},
		Minions: []SaltMinion{{Address: "address", HostGroup: "group", Hostname: &hostname, Servers: servers}},
	}
	body := bytes.NewBuffer(make([]byte, 0))
	json.NewEncoder(body).Encode(&request)
	req := httptest.NewRequest("POST", "/?index=0", body)
	req.Header.Set("salt-minion-base-dir", baseDir)

	done := make(chan struct{})
	go func() {
		SaltMinionRunRequestHandler(httptest.NewRecorder(), req)
		close(done)
	}()

	checkExecutedCommands(expectedCommands, t)
	<-done
}

func TestIsSaltMasterListChanged(t *testing.T) {
	testCases := []struct {
		name        string
		fileContent *string
		servers     []string
		expected    bool
	}{
		{name: "identical list", fileContent: strPtr("master:\n- 10.0.0.1\n- 10.0.0.2\n"), servers: []string{"10.0.0.1", "10.0.0.2"}, expected: false},
		{name: "same members in different order", fileContent: strPtr("master:\n- 10.0.0.1\n- 10.0.0.2\n- 10.0.0.3\n"), servers: []string{"10.0.0.3", "10.0.0.1", "10.0.0.2"}, expected: false},
		{name: "one master added", fileContent: strPtr("master:\n- 10.0.0.1\n"), servers: []string{"10.0.0.1", "10.0.0.2"}, expected: true},
		{name: "one master removed", fileContent: strPtr("master:\n- 10.114.128.57\n- 10.114.129.88\n- 10.114.129.67\n"), servers: []string{"10.114.129.67", "10.114.129.88"}, expected: true},
		{name: "one master replaced", fileContent: strPtr("master:\n- 10.0.0.1\n- 10.0.0.2\n"), servers: []string{"10.0.0.1", "10.0.0.3"}, expected: true},
		{name: "duplicates in new list with same members", fileContent: strPtr("master:\n- 10.0.0.1\n- 10.0.0.2\n"), servers: []string{"10.0.0.2", "10.0.0.1", "10.0.0.2"}, expected: false},
		{name: "empty original master list", fileContent: strPtr("master: []\n"), servers: []string{"10.0.0.1"}, expected: true},
		{name: "master as scalar string", fileContent: strPtr("master: 10.0.0.1\n"), servers: []string{"10.0.0.2"}, expected: false},
		{name: "file missing", fileContent: nil, servers: []string{"10.0.0.1"}, expected: false},
		{name: "file empty", fileContent: strPtr(""), servers: []string{"10.0.0.1"}, expected: false},
		{name: "invalid yaml", fileContent: strPtr("master: [10.0.0.1\n"), servers: []string{"10.0.0.1"}, expected: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			masterConfPath := t.TempDir() + "/master.conf"
			if tc.fileContent != nil {
				if err := os.WriteFile(masterConfPath, []byte(*tc.fileContent), 0644); err != nil {
					t.Fatalf("failed to write master conf: %s", err)
				}
			}

			actual := isSaltMasterListChanged(masterConfPath, tc.servers)

			if actual != tc.expected {
				t.Errorf("isSaltMasterListChanged() = %v, expected %v", actual, tc.expected)
			}
		})
	}
}

func strPtr(s string) *string {
	return &s
}

func TestSaltMinionRunRequestHandlerSucceedsWhenIdCacheCannotBeWritten(t *testing.T) {
	baseDir := t.TempDir()
	if err := os.MkdirAll(baseDir+"/etc/salt/minion_id", 0755); err != nil {
		t.Fatal(err)
	}
	originalExec := commandExecutor
	defer func() { commandExecutor = originalExec }()
	var executed []string
	commandExecutor = func(executable string, args ...string) ([]byte, error) {
		executed = append(executed, executable+" "+strings.Join(args, " "))
		return nil, nil
	}

	hostname := "host-1"
	request := SaltActionRequest{
		Master:  SaltMaster{Address: "master", Domain: "example.com"},
		Minions: []SaltMinion{{Address: "10.0.0.1", Hostname: &hostname, Roles: []string{"role"}}},
	}
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/?index=0", bytes.NewReader(body))
	req.Header.Set("salt-minion-base-dir", baseDir)
	w := httptest.NewRecorder()
	SaltMinionRunRequestHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("cache write failure must not fail provisioning, got HTTP %d: %s", w.Code, w.Body.String())
	}
	if !containsCommand(executed, "/bin/systemctl start salt-minion") {
		t.Errorf("expected salt-minion to be started, got %v", executed)
	}
}

func TestEnsureMinionIdWritesIdConfig(t *testing.T) {
	tempDirName, _ := os.MkdirTemp("", "minionidtest")
	defer os.RemoveAll(tempDirName)
	os.MkdirAll(tempDirName+"/etc/salt/minion.d", 0755)

	if _, err := ensureMinionId(tempDirName, "host-1.example.com"); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	content, _ := os.ReadFile(tempDirName + "/etc/salt/minion.d/minion_id.conf")
	var conf map[string]string
	yaml.Unmarshal(content, &conf)
	if conf["id"] != "host-1.example.com" {
		t.Errorf("expected id host-1.example.com, got %q (raw: %s)", conf["id"], string(content))
	}
}

func TestEnsureMinionIdNoDriftWhenNoCache(t *testing.T) {
	tempDirName, _ := os.MkdirTemp("", "minionidtest")
	defer os.RemoveAll(tempDirName)
	os.MkdirAll(tempDirName+"/etc/salt/minion.d", 0755)

	changed, _ := ensureMinionId(tempDirName, "host-1.example.com")
	if changed {
		t.Errorf("expected no drift when no cached minion_id exists")
	}
}

func TestEnsureMinionIdDetectsDrift(t *testing.T) {
	tempDirName, _ := os.MkdirTemp("", "minionidtest")
	defer os.RemoveAll(tempDirName)
	os.MkdirAll(tempDirName+"/etc/salt/minion.d", 0755)
	os.WriteFile(tempDirName+"/etc/salt/minion_id", []byte("stale.internal.cloudapp.net\n"), 0644)

	changed, _ := ensureMinionId(tempDirName, "host-1.example.com")
	if !changed {
		t.Errorf("expected drift when cached minion_id differs from desired id")
	}
}

func TestEnsureMinionIdPreservesCacheUntilServiceSuccess(t *testing.T) {
	baseDir := t.TempDir()
	if err := os.MkdirAll(baseDir+"/etc/salt/minion.d", 0755); err != nil {
		t.Fatal(err)
	}
	const staleId = "stale.internal.cloudapp.net\n"
	cachePath := baseDir + "/etc/salt/minion_id"
	if err := os.WriteFile(cachePath, []byte(staleId), 0644); err != nil {
		t.Fatal(err)
	}

	for attempt := 0; attempt < 2; attempt++ {
		changed, err := ensureMinionId(baseDir, "host-1.example.com")
		if err != nil {
			t.Fatal(err)
		}
		if !changed {
			t.Errorf("attempt %d: expected drift until the service succeeds", attempt+1)
		}
		cached, err := os.ReadFile(cachePath)
		if err != nil {
			t.Fatal(err)
		}
		if string(cached) != staleId {
			t.Errorf("attempt %d: expected stale cache to be preserved, got %q", attempt+1, cached)
		}
	}
}

func TestEnsureMinionIdNoDriftWhenCacheMatches(t *testing.T) {
	tempDirName, _ := os.MkdirTemp("", "minionidtest")
	defer os.RemoveAll(tempDirName)
	os.MkdirAll(tempDirName+"/etc/salt/minion.d", 0755)
	os.WriteFile(tempDirName+"/etc/salt/minion_id", []byte("host-1.example.com\n"), 0644)

	changed, _ := ensureMinionId(tempDirName, "host-1.example.com")
	if changed {
		t.Errorf("expected no drift when cached minion_id matches desired id")
	}
}

func TestEnsureMinionIdAssumesDriftWhenCacheUnreadable(t *testing.T) {
	tempDirName, _ := os.MkdirTemp("", "minionidtest")
	defer os.RemoveAll(tempDirName)
	os.MkdirAll(tempDirName+"/etc/salt/minion.d", 0755)
	// A directory where the cache file is expected makes the read fail with a
	// non-NotExist error; the pin still succeeds, so provisioning must not fail.
	os.MkdirAll(tempDirName+"/etc/salt/minion_id", 0755)

	changed, err := ensureMinionId(tempDirName, "host-1.example.com")
	if err != nil {
		t.Fatalf("an unreadable minion_id cache must not fail ensureMinionId, got: %s", err)
	}
	if !changed {
		t.Errorf("expected drift to be assumed (restart) when the cached minion_id is unreadable")
	}

	content, _ := os.ReadFile(tempDirName + "/etc/salt/minion.d/minion_id.conf")
	var conf map[string]string
	yaml.Unmarshal(content, &conf)
	if conf["id"] != "host-1.example.com" {
		t.Errorf("expected id still pinned to host-1.example.com, got %q (raw: %s)", conf["id"], string(content))
	}
}
