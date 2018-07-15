package saltboot

import (
	"encoding/json"
	"fmt"
	"github.com/hortonworks/salt-bootstrap/saltboot/model"
	"log"
	"net/http"
)

const PACKAGE_VERSION_SCRIPT = "asd"
const PACKAGE_VERSION_FILE = "asd"

type PackageVersionsRequest struct {
	Packages []string `json:"packages,omitempty"`
}

type PackageVersionsRequestOnHosts struct {
	Targets                []string               `json:"targets,omitempty"`
	PackageVersionsRequest PackageVersionsRequest `json:"packageVersionsRequest,omitempty"`
}

func (r PackageVersionsRequestOnHosts) String() string {
	b, _ := json.Marshal(r)
	return fmt.Sprintf(string(b))
}

func (r PackageVersionsRequestOnHosts) distributePackageVersionsRequest(user string, pass string, signature string, signed string) []model.Response {
	log.Print("[distributePackageVersionsRequest] distribute package versions request")
	return distributePackageVersionsRequestImpl(Distribute, r, user, pass, signature, signed)
}

func distributePackageVersionsRequestImpl(distribute func([]string, []byte, string, string, string) <-chan model.Response,
	request PackageVersionsRequestOnHosts, user string, pass string, signature string, signed string) (result []model.Response) {
	targets := request.Targets
	hostRequest := request.PackageVersionsRequest
	jsonString, _ := json.Marshal(hostRequest)
	log.Printf("[distributePackageVersionsRequestImpl] send package versions request to: %s", targets)
	for res := range distribute(targets, []byte(jsonString), PackageVersionsEP, user, pass) {
		result = append(result, res)
	}
	return result
}

func HandlePackageVersionsRequest(w http.ResponseWriter, req *http.Request) {
	log.Println("[HandlePackageVersionsRequest] execute package versions request")

	var resp model.Response

	decoder := json.NewDecoder(req.Body)
	var packageVersionsRequest PackageVersionsRequest
	err := decoder.Decode(&packageVersionsRequest)
	if err != nil {
		log.Printf("[HandlePackageVersionsRequest] [ERROR] couldn't decode json: %s", err.Error())
		resp = model.Response{ErrorText: err.Error(), StatusCode: http.StatusInternalServerError}
		resp.WriteHttp(w)
		return
	}

	packageVersions, err := getPackageVersions(packageVersionsRequest.Packages)
	if err != nil {
		log.Printf("[HandlePackageVersionsRequest] [ERROR] couldn't get the versions of the packages: %s", err.Error())
		resp = model.Response{ErrorText: err.Error(), StatusCode: http.StatusInternalServerError}
		resp.WriteHttp(w)
		return
	}
	resp = model.Response{Status: "Package versions determined", Parameters: packageVersions}
	resp.WriteHttp(w)
}

func DistributePackageVersionsRequest(w http.ResponseWriter, req *http.Request) {
	log.Println("[DistributePackageVersionsRequest] distribute package versions request")

	decoder := json.NewDecoder(req.Body)
	var request PackageVersionsRequestOnHosts
	err := decoder.Decode(&request)
	if err != nil {
		log.Printf("[DistributePackageVersionsRequest] [ERROR] couldn't decode json: %s", err.Error())
		model.Response{Status: err.Error()}.WriteBadRequestHttp(w)
		return
	}

	user, pass := GetAuthUserPass(req)
	signature, signed := GetSignatureAndSigned(req)
	result := request.distributePackageVersionsRequest(user, pass, signature, signed)
	cResp := model.Responses{Responses: result}
	log.Printf("[DistributePackageVersionsRequest] distribute package versions request executed: %s", cResp.String())
	if err := json.NewEncoder(w).Encode(cResp); err != nil {
		log.Printf("[DistributePackageVersionsRequest] [ERROR] couldn't encode json: %s", err.Error())
	}
}

func getPackageVersions(packages []string) (interface{}, error) {
	packageVersion := make(map[string]interface{})
	for _, pack := range packages {
		packageVersion[pack] = "1.0"
	}
	return packageVersion, nil
}
