package cbboot

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/sequenceiq/cloudbreak-bootstrap/cbboot/model")

func handleHealthCheck(w http.ResponseWriter, req *http.Request) {
	log.Println("[web] handleHealtchCheck executed")
	cResp :=  model.Response{Status: "OK"}
	json.NewEncoder(w).Encode(cResp)
}

func handleConsulRequest(w http.ResponseWriter, req *http.Request) {

	log.Println("[web] handleConsulRequest executed")

	var consulClusterReq model.ConsulClusterRequest
	err := json.NewDecoder(req.Body).Decode(&consulClusterReq)
	if err != nil {
		log.Println("[web] [ERROR] couldn't decode json: ", err)
	}

	cResp := executeConsulBootstrap(consulClusterReq);

	w.Header().Set("Content-Type", "application/json")
	log.Println("[web] generated response: ", cResp)
	json.NewEncoder(w).Encode(cResp)

}

func handleConsulRelayRequest(w http.ResponseWriter, req *http.Request) {

	log.Println("[web] handleConsulRequest executed")

	decoder := json.NewDecoder(req.Body)
	var consulClusterReq model.ConsulClusterRequest
	err := decoder.Decode(&consulClusterReq)
	if err != nil {
		log.Println("[web] [ERROR] couldn't decode json: ", err)
	}

	cResp := relayConsulClusterRequest(consulClusterReq);

	w.Header().Set("Content-Type", "application/json")
	log.Println("[web] generated response: ", cResp)
	json.NewEncoder(w).Encode(cResp)

}

func handleContainerRequest(w http.ResponseWriter, req *http.Request) {

	log.Println("[web] launchContainer")

	decoder := json.NewDecoder(req.Body)
	var cReq model.Request
	err := decoder.Decode(&cReq)
	if err != nil {
		log.Println("[web] [ERROR] couldn't decode json: ", err)
	}


	if(cReq.Cleanup) {
		log.Println("[web] launching cleanup container")
		cmdExecute("rm", cReq.Address, cReq.Container);
		log.Println("[web] cleanup container executed")

	}

	var outStr string
	outStr, err = cmdExecute(cReq.Cmd, cReq.Address, cReq.Container);

	log.Println("[web] generate response for: ", cReq)
	cResp := new(model.ContainerResponse)

	cResp.Fill(outStr, err)
	cResp.Container = cReq.Container

	w.Header().Set("Content-Type", "application/json")
	log.Println("[web] generated response: ", cResp)
	json.NewEncoder(w).Encode(cResp)

}



func NewCloudbreakBootstrapWeb() {

	address := fmt.Sprintf(":%d", determineBootstrapPort())

	log.Println("[web] NewCloudbreakBootstrapWeb")

	r := mux.NewRouter()
	r.HandleFunc("/cbboot/health", handleHealthCheck).Methods("GET")
	r.HandleFunc("/cbboot/container/launch", handleContainerRequest).Methods("POST")
	r.HandleFunc("/cbboot/consul/launch", handleConsulRequest).Methods("POST")
	r.HandleFunc("/cbboot/consul/relay", handleConsulRelayRequest).Methods("POST")

	log.Println("[web] starting server at:", address)
	http.Handle("/", r)
	http.ListenAndServe(address, nil)
}
