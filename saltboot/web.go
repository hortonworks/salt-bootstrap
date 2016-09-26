package saltboot

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	homedir "github.com/mitchellh/go-homedir"
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
	SaltPillarEP           = RootPath + "/salt/server/pillar"
	HostnameDistributeEP   = RootPath + "/hostname/distribute"
	HostnameEP             = RootPath + "/hostname"
	UploadEP               = RootPath + "/file"
)

func NewCloudbreakBootstrapWeb() {
	address := fmt.Sprintf(":%d", DetermineBootstrapPort())
	securityConfig, err := DetermineSecurityDetails(os.Getenv, homedir.Dir)
	if err != nil {
		log.Fatal("[web] Failed to get config details")
	}

	log.Println("[web] NewCloudbreakBootstrapWeb")

	authenticator := Authenticator{Username: securityConfig.Username, Password: securityConfig.Password}
	signature := []byte(securityConfig.SignVerifyKey)

	r := mux.NewRouter()
	r.HandleFunc(HealthEP, HealthCheckHandler).Methods("GET")
	r.Handle(ServerSaveEP, authenticator.Wrap(ServerRequestHandler, signature)).Methods("POST")
	r.Handle(ServerDistributeEP, authenticator.Wrap(ClientDistributionHandler, signature)).Methods("POST")

	r.Handle(SaltActionDistributeEP, authenticator.Wrap(SaltActionDistributeRequestHandler, signature)).Methods("POST")
	r.Handle(SaltMinionRunEP, authenticator.Wrap(SaltMinionRunRequestHandler, nil)).Methods("POST")
	r.Handle(SaltMinionStopEP, authenticator.Wrap(SaltMinionStopRequestHandler, nil)).Methods("POST")
	r.Handle(SaltServerRunEP, authenticator.Wrap(SaltServerRunRequestHandler, nil)).Methods("POST")
	r.Handle(SaltServerStopEP, authenticator.Wrap(SaltServerStopRequestHandler, nil)).Methods("POST")
	r.Handle(SaltPillarEP, authenticator.Wrap(SaltPillarRequestHandler, signature)).Methods("POST")

	r.Handle(HostnameDistributeEP, authenticator.Wrap(ClientHostnameDistributionHandler, signature)).Methods("POST")
	r.Handle(HostnameEP, authenticator.Wrap(ClientHostnameHandler, nil)).Methods("POST")

	r.Handle(UploadEP, authenticator.Wrap(FileUploadHandler, signature)).Methods("POST")

	log.Printf("[web] starting server at: %s", address)
	http.Handle("/", r)
	http.ListenAndServe(address, nil)
}
