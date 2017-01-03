package saltboot

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http/httptest"
	"os"
	"regexp"
	"testing"

	"github.com/hortonworks/salt-bootstrap/saltboot/model"
	"gopkg.in/yaml.v2"
)

func TestDistributeActionImplWithoutMaster(t *testing.T) {
	distributeRequest := func(clients []string, request SaltActionRequest, endpoint string, user string, pass string, signature string, signed string) <-chan model.Response {
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
	distributeRequest := func(clients []string, request SaltActionRequest, endpoint string, user string, pass string, signature string, signed string) <-chan model.Response {
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
	os.Setenv(ENV_TYPE, "test")
	defer os.Clearenv()

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

	SaltMinionRunRequestHandler(w, req)

	if _, err := os.Stat(tempDirName + "/etc/salt/minion.d"); os.IsNotExist(err) {
		t.Errorf("missing minion dir %s", tempDirName+"/etc/salt/minion.d")
	}

	content, _ := ioutil.ReadFile(tempDirName + "/etc/salt/minion.d/master.conf")
	expected := "master: server"
	if string(content) != expected {
		t.Errorf("master config not match %s == %s", expected, string(content))
	}

	grainYaml, _ := ioutil.ReadFile(tempDirName + "/etc/salt/grains")
	err := yaml.Unmarshal(grainYaml, &GrainConfig{})
	if err != nil {
		t.Errorf("couldn't unmarshall grain yaml: %s", err)
	}

	if os.Getenv(EXECUTED_COMMANDS) != "hostname -s:hostname -d:hostname -I:ps aux:/sbin/service salt-minion start:/sbin/chkconfig salt-minion on:" {
		t.Errorf("wrong commands were executed: %s", os.Getenv(EXECUTED_COMMANDS))
	}
}

func TestSaltMinionStopRequestHandler(t *testing.T) {
	os.Setenv(ENV_TYPE, "test")
	defer os.Clearenv()

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

	SaltMinionStopRequestHandler(w, req)

	if os.Getenv(EXECUTED_COMMANDS) != "/sbin/service salt-minion stop:/sbin/chkconfig salt-minion off:" {
		t.Errorf("wrong commands were executed: %s", os.Getenv(EXECUTED_COMMANDS))
	}
}

func TestSaltServerRunRequestHandler(t *testing.T) {
	os.Setenv(ENV_TYPE, "test")
	defer os.Clearenv()

	master := SaltMaster{}
	body := bytes.NewBuffer(make([]byte, 0))
	encoder := json.NewEncoder(body)
	encoder.Encode(&master)

	req := httptest.NewRequest("GET", "/?index=0", body)
	w := httptest.NewRecorder()

	SaltServerRunRequestHandler(w, req)

	pattern := "^hostname -s:hostname -d:hostname -I:grep saltuser /etc/passwd:adduser --no-create-home -G wheel -s /sbin/nologin --password \\$6\\$([a-zA-Z\\$0-9/.]+) saltuser:ps aux:/sbin/service salt-master start:/sbin/chkconfig salt-master on:ps aux:/sbin/service salt-api start:/sbin/chkconfig salt-api on:$"
	if m, err := regexp.MatchString(pattern, os.Getenv(EXECUTED_COMMANDS)); m == false || err != nil {
		t.Errorf("wrong commands were executed: %s", os.Getenv(EXECUTED_COMMANDS))
	}
}

func TestSaltServerStopRequestHandler(t *testing.T) {
	os.Setenv(ENV_TYPE, "test")
	defer os.Clearenv()

	req := httptest.NewRequest("GET", "/?index=0", nil)
	w := httptest.NewRecorder()

	SaltServerStopRequestHandler(w, req)

	if os.Getenv(EXECUTED_COMMANDS) != "/sbin/service salt-master stop:/sbin/chkconfig salt-master off:/sbin/service salt-api stop:/sbin/chkconfig salt-api off:" {
		t.Errorf("wrong commands were executed: %s", os.Getenv(EXECUTED_COMMANDS))
	}
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
