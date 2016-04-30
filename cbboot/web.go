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

func HealthCheckHandler(w http.ResponseWriter, req *http.Request) {
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

    address := fmt.Sprintf(":%d", DetermineBootstrapPort())
    username, password := DetermineAuthCredentials()

    log.Printf("[web] NewCloudbreakBootstrapWeb")

    authenticator := Authenticator{Username:username, Password:password}

    r := mux.NewRouter()
    r.HandleFunc(HealthEP, HealthCheckHandler).Methods("GET")
    r.Handle(ServerSaveEP, authenticator.Wrap(ServerRequestHandler)).Methods("POST")
    r.Handle(ServerDistributeEP, authenticator.Wrap(ClientDistributionHandler)).Methods("POST")
    r.Handle(ConsulConfigSaveEP, authenticator.Wrap(ConsulConfigSaveRequestHandler)).Methods("POST")
    r.Handle(ConsulConfigDistributeEP, authenticator.Wrap(ConsulConfigDistributeRequestHandler)).Methods("POST")
    r.Handle(ConsulRunEP, authenticator.Wrap(ConsulRunRequestHandler)).Methods("POST")
    r.Handle(ConsulRunDistributeEP, authenticator.Wrap(ConsulRunDistributeRequestHandler)).Methods("POST")
    r.Handle(AmbariRunDistributeEP, authenticator.Wrap(AmbariRunDistributeRequestHandler)).Methods("POST")
    r.Handle(AmbariAgentRunEP, authenticator.Wrap(AmbariAgentRunRequestHandler)).Methods("POST")
    r.Handle(AmbariServerRunEP, authenticator.Wrap(AmbariServerRunRequestHandler)).Methods("POST")
    r.Handle(SaltRunDistributeEP, authenticator.Wrap(SaltRunDistributeRequestHandler)).Methods("POST")
    r.Handle(SaltMinionRunEP, authenticator.Wrap(SaltMinionRunRequestHandler)).Methods("POST")
    r.Handle(SaltServerRunEP, authenticator.Wrap(SaltServerRunRequestHandler)).Methods("POST")
    r.Handle(SaltServerSetupEP, authenticator.Wrap(SaltServerSetupRequestHandler)).Methods("POST")
    r.Handle(HostnameDistributeEP, authenticator.Wrap(ClientHostnameDistributionHandler)).Methods("POST")
    r.Handle(HostnameEP, authenticator.Wrap(ClientHostnameHandler)).Methods("POST")

    r.Handle("/cbboot/file", authenticator.Wrap(FileUploadHandler)).Methods("POST")

    log.Printf("[web] starting server at: %s", address)
    http.Handle("/", r)
    http.ListenAndServe(address, nil)
}
