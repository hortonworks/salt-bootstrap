package saltboot

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/hortonworks/salt-bootstrap/saltboot/model"
	"gopkg.in/yaml.v2"
)

func TestDistributeActionImplWithoutMaster(t *testing.T) {
	distributeRequest := func(clients []string, endpoint string, user string, pass string, signature string, signed string) <-chan model.Response {
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

	resp := distributeActionImpl(distributeRequest, request, "user", "pass", "", "")

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
	distributeRequest := func(clients []string, endpoint string, user string, pass string, signature string, signed string) <-chan model.Response {
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

	resp := distributeActionImpl(distributeRequest, request, "user", "pass", "", "")

	if len(resp) != 1 {
		t.Errorf("size not match %d == %d", 1, len(resp))
	} else if resp[0].Address != request.Master.Address {
		t.Errorf("address not match %s == %s", request.Master.Address, resp[0].Address)
	}
}

func TestSaltMinionRunRequestHandler(t *testing.T) {
	watchCommands = true
	defer func() { watchCommands = false }()

	tempDirName, _ := ioutil.TempDir("", "saltminionruntest")
	defer os.RemoveAll(tempDirName)

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

	req := httptest.NewRequest("POST", "/?index=0", body)
	req.Header.Set("salt-minion-base-dir", tempDirName)
	w := httptest.NewRecorder()

	go func() {
		SaltMinionRunRequestHandler(w, req)

		if _, err := os.Stat(tempDirName + "/etc/salt/minion.d"); os.IsNotExist(err) {
			t.Errorf("missing minion dir %s", tempDirName+"/etc/salt/minion.d")
		}

		content, _ := ioutil.ReadFile(tempDirName + "/etc/salt/minion.d/master.conf")
		var masters map[string][]string
		yaml.Unmarshal(content, &masters)
		expected := map[string][]string{"master": []string{"server"}}
		if masters["master"][0] != expected["master"][0] {
			t.Errorf("master config not match %s == %s", expected, string(content))
		}

		grainYaml, _ := ioutil.ReadFile(tempDirName + "/etc/salt/grains")
		err := yaml.Unmarshal(grainYaml, &GrainConfig{})
		if err != nil {
			t.Errorf("couldn't unmarshall grain yaml: %s", err)
		}
	}()

	checkExecutedCommands([]string{
		"hostname -s",
		"hostname -d",
		"hostname -I",
		"hostname ",
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
		"hostname -I",
		"hostname ",
		"grep saltuser /etc/passwd",
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
	tempDirName, _ := ioutil.TempDir("", "writepillartest")
	defer os.RemoveAll(tempDirName)

	json := make(map[string]interface{})
	json["key"] = "value"
	pillar := SaltPillar{
		Path: "/path/file",
		Json: json,
	}

	_, err := writePillarImpl(pillar, tempDirName)

	if err != nil {
		t.Errorf("error occured during write %s", err)
	}

	expected := "key: value\n"
	content, _ := ioutil.ReadFile(tempDirName + "/srv/pillar" + pillar.Path)
	if string(content) != expected {
		t.Errorf("yml content not match %s == %s", expected, string(content))
	}
}
