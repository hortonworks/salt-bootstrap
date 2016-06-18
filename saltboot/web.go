package saltboot

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
)

const (
	RootPath               = "/saltboot"
	HealthEP               = RootPath + "/health"
	ServerSaveEP           = RootPath + "/server/save"
	ServerDistributeEP     = RootPath + "/server/distribute"
	SaltActionDistributeEP = RootPath + "/salt/action/distribute"
	SaltMinionEp           = RootPath + "/salt/minion"
	SaltServerEp           = RootPath + "/salt/server"
	SaltMinionRunEP        = SaltMinionEp + "/run"
	SaltMinionStopEP       = SaltMinionEp + "/stop"
	SaltServerRunEP        = SaltServerEp + "/run"
	SaltServerStopEP       = SaltServerEp + "/stop"
	SaltServerSetupEP      = RootPath + "/salt/server/setup"
	SaltPillarEP           = RootPath + "/salt/server/pillar"
	HostnameDistributeEP   = RootPath + "/hostname/distribute"
	HostnameEP             = RootPath + "/hostname"
	UploadEP               = RootPath + "/file"
)

func NewCloudbreakBootstrapWeb() {

	logFile, err := os.OpenFile("/var/log/saltboot.log", os.O_APPEND|os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		log.Printf("Error opening log file: %v", err)
	}
	defer logFile.Close()
	log.SetOutput(io.MultiWriter(os.Stdout, logFile))

	address := fmt.Sprintf(":%d", DetermineBootstrapPort())
	username, password := DetermineAuthCredentials()

	log.Printf("[web] NewCloudbreakBootstrapWeb")

	authenticator := Authenticator{Username: username, Password: password}

	r := mux.NewRouter()
	r.HandleFunc(HealthEP, HealthCheckHandler).Methods("GET")
	r.Handle(ServerSaveEP, authenticator.Wrap(ServerRequestHandler)).Methods("POST")
	r.Handle(ServerDistributeEP, authenticator.Wrap(ClientDistributionHandler)).Methods("POST")

	r.Handle(SaltActionDistributeEP, authenticator.Wrap(SaltActionDistributeRequestHandler)).Methods("POST")
	r.Handle(SaltMinionRunEP, authenticator.Wrap(SaltMinionRunRequestHandler)).Methods("POST")
	r.Handle(SaltMinionStopEP, authenticator.Wrap(SaltMinionStopRequestHandler)).Methods("POST")
	r.Handle(SaltServerRunEP, authenticator.Wrap(SaltServerRunRequestHandler)).Methods("POST")
	r.Handle(SaltServerStopEP, authenticator.Wrap(SaltServerStopRequestHandler)).Methods("POST")
	r.Handle(SaltServerSetupEP, authenticator.Wrap(SaltServerSetupRequestHandler)).Methods("POST")
	r.Handle(SaltPillarEP, authenticator.Wrap(SaltPillarRequestHandler)).Methods("POST")

	r.Handle(HostnameDistributeEP, authenticator.Wrap(ClientHostnameDistributionHandler)).Methods("POST")
	r.Handle(HostnameEP, authenticator.Wrap(ClientHostnameHandler)).Methods("POST")

	r.Handle(UploadEP, authenticator.Wrap(FileUploadHandler)).Methods("POST")

	log.Printf("[web] starting server at: %s", address)
	http.Handle("/", r)
	http.ListenAndServe(address, nil)
}
