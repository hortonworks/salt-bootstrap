package saltboot

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"

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

	go func() {
		SaltMinionRunRequestHandler(w, req)

		if _, err := os.Stat(tempDirName + "/etc/salt/minion.d"); os.IsNotExist(err) {
			t.Errorf("missing minion dir %s", tempDirName+"/etc/salt/minion.d")
		}

		content, _ := os.ReadFile(tempDirName + "/etc/salt/minion.d/master.conf")
		var masters map[string][]string
		yaml.Unmarshal(content, &masters)
		expected := map[string][]string{"master": {"server"}}
		if masters["master"][0] != expected["master"][0] {
			t.Errorf("master config not match %s == %s", expected, string(content))
		}

		grainYaml, _ := os.ReadFile(tempDirName + "/etc/salt/grains")
		err := yaml.Unmarshal(grainYaml, &GrainConfig{})
		if err != nil {
			t.Errorf("couldn't unmarshall grain yaml: %s", err)
		}
		os.RemoveAll(tempDirName)
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
