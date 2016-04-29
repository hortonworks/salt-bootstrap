package cbboot

import (
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "github.com/gorilla/mux"
    "github.com/sequenceiq/cloudbreak-bootstrap/cbboot/model"
    "os"
    "io"
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
	SaltRunDistributeEP = RootPath + "/salt/run/distribute"
	SaltMinionRunEP = RootPath + "/salt/minion/run"
	SaltServerRunEP = RootPath + "/salt/server/run"
    SaltServerSetupEP = RootPath + "/salt/server/setup"
    HostnameDistributeEP = RootPath + "/hostname/distribute"
    HostnameEP = RootPath + "/hostname"
)

func healthCheckHandler(w http.ResponseWriter, req *http.Request) {
    log.Printf("[web] handleHealtchCheck executed")
    cResp := model.Response{Status: "OK"}
    json.NewEncoder(w).Encode(cResp)
}

func NewCloudbreakBootstrapWeb() {

    logFile, err := os.OpenFile("/var/log/cbboot.log", os.O_APPEND | os.O_CREATE | os.O_RDWR, 0666)
    if err != nil {
        log.Printf("Error opening log file: %v", err)
    }
    defer logFile.Close()
    log.SetOutput(io.MultiWriter(os.Stdout, logFile))

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
    r.Handle(SaltRunDistributeEP, authenticator.wrap(SaltRunDistributeRequestHandler)).Methods("POST")
    r.Handle(SaltMinionRunEP, authenticator.wrap(SaltMinionRunRequestHandler)).Methods("POST")
    r.Handle(SaltServerRunEP, authenticator.wrap(SaltServerRunRequestHandler)).Methods("POST")
    r.Handle(SaltServerSetupEP, authenticator.wrap(SaltServerSetupRequestHandler)).Methods("POST")
    r.Handle(HostnameDistributeEP, authenticator.wrap(ClientHostnameDistributionHandler)).Methods("POST")
    r.Handle(HostnameEP, authenticator.wrap(ClientHostnameHandler)).Methods("POST")

    r.Handle("/cbboot/file", authenticator.wrap(fileUploadHandler)).Methods("POST")

    log.Printf("[web] starting server at: %s", address)
    http.Handle("/", r)
    http.ListenAndServe(address, nil)
}
