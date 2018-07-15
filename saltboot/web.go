package saltboot

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

const (
	RootPath                    = "/saltboot"
	HealthEP                    = RootPath + "/health"
	ServerSaveEP                = RootPath + "/server/save"
	ServerDistributeEP          = RootPath + "/server/distribute"
	SaltActionDistributeEP      = RootPath + "/salt/action/distribute"
	SaltMinionEp                = RootPath + "/salt/minion"
	SaltServerEp                = RootPath + "/salt/server"
	SaltMinionRunEP             = SaltMinionEp + "/run"
	SaltMinionStopEP            = SaltMinionEp + "/stop"
	SaltServerRunEP             = SaltServerEp + "/run"
	SaltServerStopEP            = SaltServerEp + "/stop"
	SaltPillarEP                = RootPath + "/salt/server/pillar"
	SaltPillarDistributeEP      = SaltPillarEP + "/distribute"
	HostnameDistributeEP        = RootPath + "/hostname/distribute"
	HostnameEP                  = RootPath + "/hostname"
	UploadEP                    = RootPath + "/file"
	FileDistributeEP            = UploadEP + "/distribute"
	PackageVersionsEP           = RootPath + "/packageVersions"
	PackageVersionsDistributeEp = PackageVersionsEP + "/distribute"
)

func NewCloudbreakBootstrapWeb() {
	address := fmt.Sprintf(":%d", DetermineBootstrapPort())
	log.Println("[web] NewCloudbreakBootstrapWeb")

	authenticator := Authenticator{}

	r := mux.NewRouter()
	r.HandleFunc(HealthEP, HealthCheckHandler).Methods("GET")
	r.Handle(ServerSaveEP, authenticator.Wrap(ServerRequestHandler, SIGNED)).Methods("POST")
	r.Handle(ServerDistributeEP, authenticator.Wrap(ClientDistributionHandler, SIGNED)).Methods("POST")

	r.Handle(SaltActionDistributeEP, authenticator.Wrap(SaltActionDistributeRequestHandler, SIGNED)).Methods("POST")
	r.Handle(SaltMinionRunEP, authenticator.Wrap(SaltMinionRunRequestHandler, SIGNED)).Methods("POST")
	r.Handle(SaltMinionStopEP, authenticator.Wrap(SaltMinionStopRequestHandler, SIGNED)).Methods("POST")
	r.Handle(SaltServerRunEP, authenticator.Wrap(SaltServerRunRequestHandler, SIGNED)).Methods("POST")
	r.Handle(SaltServerStopEP, authenticator.Wrap(SaltServerStopRequestHandler, SIGNED)).Methods("POST")
	r.Handle(SaltPillarEP, authenticator.Wrap(SaltPillarRequestHandler, SIGNED)).Methods("POST")
	r.Handle(SaltPillarDistributeEP, authenticator.Wrap(SaltPillarDistributeRequestHandler, SIGNED)).Methods("POST")

	r.Handle(HostnameDistributeEP, authenticator.Wrap(ClientHostnameDistributionHandler, SIGNED)).Methods("POST")
	r.Handle(HostnameEP, authenticator.Wrap(ClientHostnameHandler, OPEN)).Methods("POST")

	r.Handle(UploadEP, authenticator.Wrap(FileUploadHandler, SIGNED)).Methods("POST")
	r.Handle(FileDistributeEP, authenticator.Wrap(FileUploadDistributeHandler, SIGNED)).Methods("POST")

	r.Handle(PackageVersionsEP, authenticator.Wrap(HandlePackageVersionsRequest, OPEN)).Methods("POST")
	r.Handle(PackageVersionsDistributeEp, authenticator.Wrap(DistributePackageVersionsRequest, OPEN)).Methods("POST")
	log.Printf("[web] starting server at: %s", address)
	http.Handle("/", r)
	if err := http.ListenAndServe(address, nil); err != nil {
		log.Printf("[web] [ERROR] unable to ListenAndServe: %s", err.Error())
	}
}
