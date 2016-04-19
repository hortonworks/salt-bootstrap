package cbboot

import (
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "github.com/gorilla/mux"
    "github.com/sequenceiq/cloudbreak-bootstrap/cbboot/model"
)

const (
    RootPath = "/cbboot"
    HealthEP = RootPath + "/health"
    ServerSaveEP = RootPath + "/server/save"
    ServerDistributeEP = RootPath + "/server/distribute"
    ConsulConfigSaveEP = RootPath + "/consul/config/save"
    ConsulConfigDistributeEP = RootPath + "/consul/config/distribute"
    ConsulRunEP = RootPath + "/consul/run"
    ConsulRunDistributeEP = RootPath + "/consul/run/distribute"
    AmbariRunDistributeEP = RootPath + "/ambari/run/distribute"
    AmbariAgentRunEP = RootPath + "/ambari/agent/run"
    AmbariServerRunEP = RootPath + "/ambari/server/run"
)

func healthCheckHandler(w http.ResponseWriter, req *http.Request) {
    log.Printf("[web] handleHealtchCheck executed")
    cResp := model.Response{Status: "OK"}
    json.NewEncoder(w).Encode(cResp)
}

func NewCloudbreakBootstrapWeb() {

    address := fmt.Sprintf(":%d", determineBootstrapPort())
    username, password := determineAuthCredentials()

    log.Printf("[web] NewCloudbreakBootstrapWeb")

    authenticator := Authenticator{Username:username, Password:password}

    r := mux.NewRouter()
    r.HandleFunc(HealthEP, healthCheckHandler).Methods("GET")
    r.Handle(ServerSaveEP, authenticator.wrap(serverRequestHandler)).Methods("POST")
    r.Handle(ServerDistributeEP, authenticator.wrap(clientDistributionHandler)).Methods("POST")
    r.Handle(ConsulConfigSaveEP, authenticator.wrap(consulConfigSaveRequestHandler)).Methods("POST")
    r.Handle(ConsulConfigDistributeEP, authenticator.wrap(consulConfigDistributeRequestHandler)).Methods("POST")
    r.Handle(ConsulRunEP, authenticator.wrap(consulRunRequestHandler)).Methods("POST")
    r.Handle(ConsulRunDistributeEP, authenticator.wrap(consulRunDistributeRequestHandler)).Methods("POST")
    r.Handle(AmbariRunDistributeEP, authenticator.wrap(ambariRunDistributeRequestHandler)).Methods("POST")
    r.Handle(AmbariAgentRunEP, authenticator.wrap(ambariAgentRunRequestHandler)).Methods("POST")
    r.Handle(AmbariServerRunEP, authenticator.wrap(ambariServerRunRequestHandler)).Methods("POST")

    r.Handle("/cbboot/file", authenticator.wrap(fileUploadHandler)).Methods("POST")

    log.Printf("[web] starting server at: %s", address)
    http.Handle("/", r)
    http.ListenAndServe(address, nil)
}
