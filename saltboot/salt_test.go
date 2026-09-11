package saltboot

import (
	"bytes"
	"encoding/json"
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

	go SaltMinionRunRequestHandler(w, req)

	// The handler writes its config files before launching the minion, so once
	// the launch commands have flowed through, the files are guaranteed present.
	checkExecutedCommands([]string{
		"hostname -d",
		"hostname testhostname.example.com",
		"grep SUSE /etc/issue",
		"grep sles12 /etc/issue",
		"ps aux",
		"/bin/systemctl start salt-minion",
		"/bin/systemctl enable salt-minion",
	}, t)

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

	go SaltMinionRunRequestHandler(w, req)

	executed := drainCommands(time.Second)

	if !containsCommand(executed, "/bin/systemctl restart salt-minion") {
		t.Errorf("expected salt-minion restart on id drift, got commands: %v", executed)
	}
	if containsCommand(executed, "/bin/systemctl start salt-minion") {
		t.Errorf("expected restart (not start) on id drift, got commands: %v", executed)
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

func TestEnsureMinionIdConvergesCacheToAvoidRepeatRestart(t *testing.T) {
	tempDirName, _ := os.MkdirTemp("", "minionidtest")
	defer os.RemoveAll(tempDirName)
	os.MkdirAll(tempDirName+"/etc/salt/minion.d", 0755)
	os.WriteFile(tempDirName+"/etc/salt/minion_id", []byte("stale.internal.cloudapp.net\n"), 0644)

	// First run: stale cache -> drift -> the running minion must restart.
	first, _ := ensureMinionId(tempDirName, "host-1.example.com")
	if !first {
		t.Fatalf("expected drift on first run with a stale cached minion_id")
	}

	// salt does not rewrite /etc/salt/minion_id once `id:` is statically defined,
	// so saltboot must converge the cache itself. Otherwise every later run keeps
	// seeing the stale cache as drift and restarts the minion every time.
	second, _ := ensureMinionId(tempDirName, "host-1.example.com")
	if second {
		t.Errorf("expected no drift on second run; cache should have converged to the pinned id")
	}
	cached, _ := os.ReadFile(tempDirName + "/etc/salt/minion_id")
	if strings.TrimSpace(string(cached)) != "host-1.example.com" {
		t.Errorf("expected cached minion_id to converge to host-1.example.com, got %q", string(cached))
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
