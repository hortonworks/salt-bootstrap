package cbboot

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/mux")

func handleHealtchCheck(w http.ResponseWriter, req *http.Request) {
	log.Println("[web] handleHealtchCheck executed")
	cResp :=  Response{Status: "OK"}
	json.NewEncoder(w).Encode(cResp)

}

func handleContainerRequest(w http.ResponseWriter, req *http.Request) {
	log.Println("[web] launchContainer")

	decoder := json.NewDecoder(req.Body)
	var cReq Request
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
	cResp := new(ContainerResponse)
	if err != nil {
		log.Println("[web] [ERROR] cannot start container: ", err)
		cResp.Status = "ERR"
		cResp.ErrorText =  strings.TrimSpace(outStr + " " + err.Error())
	} else {
		cResp.Status = "OK"
	}

	cResp.Container = cReq.Container
	w.Header().Set("Content-Type", "application/json")
	log.Println("[web] generated response: ", cResp)
	json.NewEncoder(w).Encode(cResp)

}



func NewCloudbreakBootstrapWeb() {

	address := ":9090"

	port := os.Getenv("CBBOOT_PORT")
	if port != "" {
		address = fmt.Sprintf(":%s", port)
	}
	log.Println("[web] NewCloudbreakBootstrapWeb")

	r := mux.NewRouter()
	r.HandleFunc("/cbboot/health", handleHealtchCheck).Methods("GET")
	r.HandleFunc("/cbboot/launch", handleContainerRequest).Methods("POST")

	log.Println("[web] starting server at:", address)
	http.Handle("/", r)
	http.ListenAndServe(address, nil)
}
