package saltboot

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"strconv"

	"github.com/hortonworks/salt-bootstrap/saltboot/model"
	"gopkg.in/yaml.v2"
)

type SaltActionRequest struct {
	Master  SaltMaster   `json:"master,omitempty"`
	Masters []SaltMaster `json:"masters,omitempty"`
	Minions []SaltMinion `json:"minions,omitempty"`
	Action  string       `json:"action"`
	Cloud   *Cloud       `json:"cloud"`
	OS      *Os          `json:"os"`
}

type Cloud struct {
	Name string
}

type Os struct {
	Name string
}

type SaltAuth struct {
	Password string `json:"password,omitempty"`
}

type SaltMaster struct {
	Address  string   `json:"address"`
	Auth     SaltAuth `json:"auth,omitempty"`
	Hostname *string  `json:"hostName,omitempty"`
	Domain   string   `json:"domain,omitempty"`
}

type SaltMinion struct {
	Address   string   `json:"address"`
	Roles     []string `json:"roles,omitempty"`
	Server    string   `json:"server,omitempty"`
	Servers   []string `json:"servers,omitempty"`
	HostGroup string   `json:"hostGroup,omitempty"`
	Hostname  *string  `json:"hostName,omitempty"`
	Domain    string   `json:"domain,omitempty"`
}

type SaltPillar struct {
	Path    string                 `json:"path"`
	Json    map[string]interface{} `json:"json"`
	Targets []string               `json:"targets"`
}

func (saltMinion SaltMinion) AsByteArray() []byte {
	b, _ := json.Marshal(saltMinion)
	return b
}

func (saltMaster SaltMaster) AsByteArray() []byte {
	b, _ := json.Marshal(saltMaster)
	return b
}

type GrainConfig struct {
	HostGroup string   `json:"hostgroup" yaml:"hostgroup"`
	Roles     []string `json:"roles" yaml:"roles"`
}

func (r SaltActionRequest) String() string {
	b, _ := json.Marshal(r)
	return fmt.Sprintf(string(b))
}

func (r SaltActionRequest) distributeAction(user string, pass string, signature string, signed string) []model.Response {
	log.Print("[distributeAction] distribute salt state command to targets")
	return distributeActionImpl(DistributeRequest, r, user, pass, signature, signed)
}

func distributeActionImpl(distributeActionRequest func([]string, string, string, string, string, string) <-chan model.Response,
	request SaltActionRequest, user string, pass string, signature string, signed string) (result []model.Response) {
	var targets []string
	for _, minion := range request.Minions {
		targets = append(targets, minion.Address)
	}

	action := strings.ToLower(request.Action)
	log.Printf("[distributeActionImpl] send action request to minions: %s", targets)
	for res := range distributeActionRequest(targets, SaltMinionEp+"/"+action, user, pass, signature, signed) {
		result = append(result, res)
	}

	if request.Masters != nil && len(request.Masters) > 0 {
		var masters []string
		for _, master := range request.Masters {
			masters = append(masters, master.Address)
		}
		log.Printf("[distributeActionImpl] send action request to masters: %s", masters)
		for res := range distributeActionRequest(masters, SaltServerEp+"/"+action, user, pass, signature, signed) {
			result = append(result, res)
		}
	} else if len(request.Master.Address) > 0 {
		log.Printf("[distributeActionImpl] send action request to master: %s", request.Master.Address)
		result = append(result, <-distributeActionRequest([]string{request.Master.Address}, SaltServerEp+"/"+action, user, pass, signature, signed))
	}
	return result
}

func SaltMinionRunRequestHandler(w http.ResponseWriter, req *http.Request) {
	log.Println("[SaltMinionRunRequestHandler] execute salt-minion run request")

	var resp model.Response

	decoder := json.NewDecoder(req.Body)
	var saltActionRequest SaltActionRequest
	err := decoder.Decode(&saltActionRequest)
	if err != nil {
		log.Printf("[SaltMinionRunRequestHandler] [ERROR] couldn't decode json: %s", err.Error())
		resp = model.Response{ErrorText: err.Error(), StatusCode: http.StatusInternalServerError}
		resp.WriteHttp(w)
		return
	}

	index, err := strconv.Atoi(req.URL.Query().Get("index"))
	if err != nil {
		log.Printf("[SaltMinionRunRequestHandler] [ERROR] missing index: %s", err.Error())
		resp = model.Response{ErrorText: err.Error(), StatusCode: http.StatusInternalServerError}
		resp.WriteHttp(w)
		return
	}
	saltMinion := saltActionRequest.Minions[index]
	if saltMinion.Server == "" {
		saltMinion.Server = saltActionRequest.Master.Address
	}
	if saltMinion.Domain == "" {
		saltMinion.Domain = saltActionRequest.Master.Domain
	}

	err = ensureHostIsResolvable(saltMinion.Hostname, saltMinion.Domain, saltMinion.Address, saltActionRequest.OS, saltActionRequest.Cloud)
	if err != nil {
		log.Printf("[SaltMinionRunRequestHandler] [ERROR] unable to set the fqdn: %s", err.Error())
		resp = model.Response{ErrorText: err.Error(), StatusCode: http.StatusInternalServerError}
		resp.WriteHttp(w)
		return
	}

	baseDir := req.Header.Get("salt-minion-base-dir")

	err = os.MkdirAll(baseDir+"/etc/salt/minion.d", 0755)
	if err != nil {
		resp = model.Response{ErrorText: err.Error(), StatusCode: http.StatusInternalServerError}
		resp.WriteHttp(w)
		return
	}

	var masterConf []byte
	servers := saltMinion.Servers
	var restartNeeded bool
	if servers != nil && len(servers) > 0 {
		log.Printf("[SaltMinionRunRequestHandler] salt master list: %s", servers)
		masterConf, _ = yaml.Marshal(map[string][]string{"master": servers})
		restartNeeded = isSaltMinionRestartNeeded(servers)
	} else {
		log.Printf("[SaltMinionRunRequestHandler] salt master (depricated): %s", saltMinion.Server)
		masterConf, _ = yaml.Marshal(map[string][]string{"master": {saltMinion.Server}})
		restartNeeded = isSaltMinionRestartNeeded([]string{saltMinion.Server})
	}

	err = ioutil.WriteFile(baseDir+"/etc/salt/minion.d/master.conf", masterConf, 0644)
	if err != nil {
		resp = model.Response{ErrorText: err.Error(), StatusCode: http.StatusInternalServerError}
		resp.WriteHttp(w)
		return
	}

	grainConfigPath := baseDir + "/etc/salt/grains"
	if isGrainsConfigNeeded(grainConfigPath) {
		grainConfig := GrainConfig{Roles: saltMinion.Roles, HostGroup: saltMinion.HostGroup}
		grainYaml, err := yaml.Marshal(grainConfig)
		if err != nil {
			resp = model.Response{ErrorText: err.Error(), StatusCode: http.StatusInternalServerError}
			resp.WriteHttp(w)
			return
		}
		err = ioutil.WriteFile(grainConfigPath, grainYaml, 0644)
		if err != nil {
			resp = model.Response{ErrorText: err.Error(), StatusCode: http.StatusInternalServerError}
			resp.WriteHttp(w)
			return
		}
	}

	log.Println("[SaltMinionRunRequestHandler] execute salt-minion run request")
	if restartNeeded {
		resp, _ = RestartService("salt-minion")
		resp.WriteHttp(w)
	} else {
		resp, _ = LaunchService("salt-minion")
		resp.WriteHttp(w)
	}
}

func SaltMinionStopRequestHandler(w http.ResponseWriter, req *http.Request) {
	log.Println("[SaltMinionStopRequestHandler] execute salt-minion stop request")

	resp, _ := StopService("salt-minion")
	resp.WriteHttp(w)
}

func SaltServerRunRequestHandler(w http.ResponseWriter, req *http.Request) {
	log.Println("[SaltServerRunRequestHandler] execute salt run request")

	decoder := json.NewDecoder(req.Body)
	var saltActionRequest SaltActionRequest
	if err := decoder.Decode(&saltActionRequest); err != nil {
		log.Printf("[SaltServerRunRequestHandler] [ERROR] couldn't decode json: %s", err.Error())
		model.Response{Status: err.Error()}.WriteBadRequestHttp(w)
		return
	}

	index, err := strconv.Atoi(req.URL.Query().Get("index"))
	if err != nil {
		log.Printf("[SaltMinionRunRequestHandler] [ERROR] missing index: %s", err.Error())
		model.Response{Status: err.Error()}.WriteBadRequestHttp(w)
		return
	}

	var saltMaster SaltMaster
	masters := saltActionRequest.Masters
	if masters != nil && len(masters) > 0 {
		saltMaster = masters[index]
	} else {
		saltMaster = saltActionRequest.Master
	}

	var resp model.Response

	if err := ensureHostIsResolvable(saltMaster.Hostname, saltMaster.Domain, saltMaster.Address, saltActionRequest.OS, saltActionRequest.Cloud); err != nil {
		log.Printf("[SaltServerRunRequestHandler] [ERROR] unable to set the fqdn: %s", err.Error())
		resp = model.Response{ErrorText: err.Error(), StatusCode: http.StatusInternalServerError}
		resp.WriteHttp(w)
		return
	}

	var responses []model.Response

	resp, err = CreateUser(saltMaster, saltActionRequest.OS)
	if err != nil {
		resp.WriteHttp(w)
		return
	}
	responses = append(responses, resp)

	resp, err = LaunchService("salt-master")
	if err != nil {
		resp.WriteHttp(w)
		return
	}
	responses = append(responses, resp)

	resp, err = LaunchService("salt-api")
	if err != nil {
		resp.WriteHttp(w)
		return
	}
	responses = append(responses, resp)

	var message string
	for _, r := range responses {
		message += r.Status + "; "
	}
	finalResponse := model.Response{Status: message, StatusCode: http.StatusOK}
	finalResponse.WriteHttp(w)
}

func SaltServerStopRequestHandler(w http.ResponseWriter, req *http.Request) {
	log.Println("[SaltServerStopRequestHandler] execute salt master stop request")
	resp, err := StopService("salt-master")
	resp.WriteHttp(w)
	if err != nil {
		return
	}
	resp, _ = StopService("salt-api")
	resp.WriteHttp(w)
}

func (pillar SaltPillar) WritePillar() (outStr string, err error) {
	return writePillarImpl(pillar, "")
}

func writePillarImpl(pillar SaltPillar, basePath string) (outStr string, err error) {
	file := basePath + "/srv/pillar" + pillar.Path
	dir := file[0:strings.LastIndex(file, "/")]

	log.Printf("[SaltPillar.WritePillar] mkdir %s", dir)
	err = os.MkdirAll(dir, 0744)
	if err != nil {
		return "Failed to create dir " + dir, err
	}

	yml, _ := yaml.Marshal(pillar.Json)
	err = ioutil.WriteFile(file, yml, 0644)
	if err != nil {
		return "Failed to write to " + file, err
	}
	return "Salt pillar successfully written to " + file, err
}

func SaltPillarRequestHandler(w http.ResponseWriter, req *http.Request) {
	log.Println("[SaltPillarRequestHandler] execute salt pillar save request")
	decoder := json.NewDecoder(req.Body)
	var saltPillar SaltPillar
	err := decoder.Decode(&saltPillar)
	if err != nil {
		log.Printf("[SaltPillarRequestHandler] [ERROR] couldn't decode json: %s", err.Error())
		model.Response{Status: err.Error()}.WriteBadRequestHttp(w)
		return
	}

	if !strings.HasSuffix(saltPillar.Path, ".sls") {
		log.Printf("[SaltPillarRequestHandler] [ERROR] path is not ending with '.sls' suffix %s", saltPillar.Path)
		model.Response{Status: "path is not ending with '.sls' suffix"}.WriteBadRequestHttp(w)
		return
	}
	if !strings.HasPrefix(saltPillar.Path, "/") {
		log.Printf("[SaltPillarRequestHandler] [ERROR] path is not starting with '/' %s", saltPillar.Path)
		model.Response{Status: "path is not starting with '/'"}.WriteBadRequestHttp(w)
		return
	}
	if strings.Contains(saltPillar.Path, "..") {
		log.Printf("[SaltPillarRequestHandler] [ERROR] path cannot contain '..' characters %s", saltPillar.Path)
		model.Response{Status: "path cannot contain '..' characters"}.WriteBadRequestHttp(w)
		return
	}

	outStr, err := saltPillar.WritePillar()
	if err != nil {
		log.Printf("[SaltPillarRequestHandler] [ERROR] failed to execute salt pillar save config: %s", err.Error())
		model.Response{ErrorText: err.Error(), StatusCode: http.StatusInternalServerError}.WriteHttp(w)
	} else {
		cResp := model.Response{Status: outStr}.WriteHttp(w)
		log.Printf("[SaltPillarRequestHandler] save salt pillar request executed: %s", cResp.String())
	}
}

func SaltActionDistributeRequestHandler(w http.ResponseWriter, req *http.Request) {
	log.Println("[SaltActionDistributeRequestHandler] execute Salt state distribute request")

	decoder := json.NewDecoder(req.Body)
	var saltActionRequest SaltActionRequest
	err := decoder.Decode(&saltActionRequest)
	if err != nil {
		log.Printf("[SaltActionDistributeRequestHandler] [ERROR] couldn't decode json: %s", err.Error())
		model.Response{Status: err.Error()}.WriteBadRequestHttp(w)
		return
	}

	user, pass := GetAuthUserPass(req)
	signature, signed := GetSignatureAndSigned(req)
	result := saltActionRequest.distributeAction(user, pass, signature, signed)
	cResp := model.Responses{Responses: result}
	log.Printf("[SaltActionDistributeRequestHandler] distribute salt state command request executed: %s", cResp.String())
	if err := json.NewEncoder(w).Encode(cResp); err != nil {
		log.Printf("[SaltActionDistributeRequestHandler] [ERROR] couldn't encode json: %s", err.Error())
	}
}

func SaltPillarDistributeRequestHandler(w http.ResponseWriter, req *http.Request) {
	log.Println("[SaltPillarDistributeRequestHandler] execute Salt pillar distribute request")

	decoder := json.NewDecoder(req.Body)
	var saltPillar SaltPillar
	err := decoder.Decode(&saltPillar)
	if err != nil {
		log.Printf("[SaltPillarDistributeRequestHandler] [ERROR] couldn't decode json: %s", err.Error())
		model.Response{Status: err.Error()}.WriteBadRequestHttp(w)
		return
	}

	user, pass := GetAuthUserPass(req)
	signature, signed := GetSignatureAndSigned(req)

	log.Printf("[SaltPillarDistributeRequestHandler] send pillar save request to nodes: %s", saltPillar.Targets)
	result := distributePillarImpl(DistributeRequest, saltPillar, user, pass, signature, signed)

	cResp := model.Responses{Responses: result}
	log.Printf("[SaltPillarDistributeRequestHandler] distribute salt pillar request executed: %s", cResp.String())
	if err := json.NewEncoder(w).Encode(cResp); err != nil {
		log.Printf("[SaltActionDistributeRequestHandler] [ERROR] couldn't encode json: %s", err.Error())
	}
}

func distributePillarImpl(distributeActionRequest func([]string, string, string, string, string, string) <-chan model.Response,
	request SaltPillar, user string, pass string, signature string, signed string) (result []model.Response) {
	for res := range distributeActionRequest(request.Targets, SaltPillarEP, user, pass, signature, signed) {
		result = append(result, res)
	}
	return result
}

func isGrainsConfigNeeded(grainConfigLocation string) bool {
	log.Println("[isGrainsConfigNeeded] check whether salt grains are empty, config file: " + grainConfigLocation)
	b, err := ioutil.ReadFile(grainConfigLocation)
	if err == nil && len(b) > 0 {
		var grains GrainConfig = GrainConfig{}
		if err := yaml.Unmarshal(b, &grains); err != nil {
			log.Printf("[isGrainsConfigNeeded] [ERROR] failed to unmarshal grain config file: %s", err.Error())
			return true
		}
		if grains.Roles != nil && len(grains.Roles) > 0 {
			log.Printf("[isGrainsConfigNeeded] there are roles already defined: %s, no need to create new config", grains.Roles)
			return false
		}
	}
	log.Println("[isGrainsConfigNeeded] there is no grain config present at the moment, config is required")
	return true
}

func isSaltMinionRestartNeeded(servers []string) bool {
	log.Println("[isSaltMinionRestartNeeded] check whether salt-minion requires restart")
	masterConfFile := "/etc/salt/minion.d/master.conf"
	b, err := ioutil.ReadFile(masterConfFile)
	if err == nil && len(b) > 0 {
		var saltMasterIps map[string][]string = make(map[string][]string)
		if err := yaml.Unmarshal(b, saltMasterIps); err != nil {
			log.Printf("[isSaltMinionRestartNeeded] [ERROR] failed to unmarshal salt master config file: %s", err.Error())
			return false
		}
		ipList := saltMasterIps["master"]
		log.Printf("[isSaltMinionRestartNeeded] original master IP list: %s", ipList)
		for _, server := range servers {
			newMaster := true
			for _, ip := range ipList {
				if ip == server {
					newMaster = false
				}
			}
			if newMaster {
				log.Printf("[isSaltMinionRestartNeeded] found new salt-master: %s, restart needed", server)
				return true
			}
		}
	}
	log.Println("[isSaltMinionRestartNeeded] there is no new salt-master")
	return false
}
