package saltboot

import (
	"encoding/json"
	"fmt"
	"github.com/hortonworks/salt-bootstrap/saltboot/cautils"
	"github.com/hortonworks/salt-bootstrap/saltboot/model"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
)

type Credentials struct {
	Clients
	PublicIP *string `json:"PublicIP" yaml:"PublicIP"`
}

func ClientCredsHandler(w http.ResponseWriter, req *http.Request) {

	decoder := json.NewDecoder(req.Body)
	var credentials Credentials
	err := decoder.Decode(&credentials)
	if err != nil {
		log.Printf("[ClientCredsHandler] [ERROR] couldn't decode json: %s", err.Error())
		model.Response{Status: err.Error()}.WriteBadRequestHttp(w)
		return
	}

	// mkdir if needed
	log.Printf("[CAHandler] handleClientCreds executed")
	w.Header().Set("Content-Type", "application/json")
	pubIp := credentials.PublicIP

	if cautils.IsPathExisting("./tlsauth") == false {
		if err := os.Mkdir("./tlsauth", 0755); err != nil {
			fmt.Fprintf(w, "FAIL")
			return
		}
	}
	caResp, _ := http.Get("http://" + credentials.Servers[0].Address + ":7070/saltboot/ca")
	caBytes, _ := ioutil.ReadAll(caResp.Body)
	caCrt, err := cautils.NewCertificateFromPEM(caBytes)
	if err != nil {
		fmt.Fprintf(w, "FAIL")
		panic(err)
	}
	err = caCrt.ToPEMFile("./tlsauth/ca.crt")
	if cautils.IsPathExisting("./tlsauth/client.key") == false {
		key, err := cautils.NewKey()
		if err != nil {
			fmt.Fprintf(w, "FAIL")
			panic(err)
		}

		err = key.ToPEMFile("./tlsauth/client.key")
		if err != nil {
			fmt.Fprintf(w, "FAIL")
			panic(err)
		}
	}
	if cautils.IsPathExisting("./tlsauth/client.csr") == false {
		key, err := cautils.NewKeyFromPrivateKeyPEMFile("./tlsauth/client.key")
		if err != nil {
			fmt.Fprintf(w, "FAIL")
			panic(err)
		}

		csr, err := cautils.NewCertificateRequest(key, pubIp)
		if err != nil {
			fmt.Fprintf(w, "FAIL")
			panic(err)
		}
		err = csr.ToPEMFile("./tlsauth/client.csr")
		if err != nil {
			fmt.Fprintf(w, "FAIL")
			panic(err)
		}
	}
	csr, err := cautils.NewCertificateRequestFromPEMFile("./tlsauth/client.csr")
	if err != nil {
		fmt.Fprintf(w, "FAIL")
		panic(err)
	}
	pem, _ := csr.ToPEM()
	data := make(url.Values)
	data.Add("csr", string(pem))
	//resp, err := http.PostForm("http://" + host + "/certificates", data)
	resp, _ := http.PostForm("http://"+credentials.Servers[0].Address+":7070/saltboot/csr", data)
	crtBytes, _ := ioutil.ReadAll(resp.Body)
	crt, err := cautils.NewCertificateFromPEM(crtBytes)
	if err != nil {
		fmt.Fprintf(w, "FAIL")
		panic(err)
	}
	err = crt.ToPEMFile("./tlsauth/client.crt")
	fmt.Fprintf(w, "OK")
}

func ClientCredsDistributeHandler(w http.ResponseWriter, req *http.Request) {
	log.Println("[ClientCredsDistributeHandler] execute distribute hostname request")

	decoder := json.NewDecoder(req.Body)
	var credentials Credentials
	err := decoder.Decode(&credentials)
	if err != nil {
		log.Printf("[ClientCredsDistributeHandler] [ERROR] couldn't decode json: %s", err)
		model.Response{Status: err.Error()}.WriteBadRequestHttp(w)
		return
	}

	user, pass := GetAuthUserPass(req)
	responses := credentials.DistributeClientCredentials(user, pass)
	cResp := model.Responses{Responses: responses}
	log.Printf("[ClientCredsDistributeHandler] distribute request executed: %s" + cResp.String())
	json.NewEncoder(w).Encode(cResp)
}

func (credentials *Credentials) DistributeClientCredentials(user string, pass string) []model.Response {
	log.Printf("[Clients.DistributeClientCredentials] Request: %v", credentials)
	credReq := Credentials{
		Clients: Clients{
			Servers: credentials.Servers,
		},
		PublicIP: credentials.PublicIP,
	}
	jsonBody, _ := json.Marshal(credReq)
	distributeImpl(Distribute, []string{credentials.Servers[0].Address}, jsonBody, ClientCredsEP, user, pass)

	credReq.PublicIP = nil
	jsonBody, _ = json.Marshal(credReq)
	//TODO fix response
	return distributeImpl(Distribute, credentials.Clients.Clients, jsonBody, ClientCredsEP, user, pass)
}
