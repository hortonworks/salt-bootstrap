package saltboot

import (
	"fmt"
	"github.com/gorilla/mux"
	"log"
	"net/http"
)

const (
	RootPath                   = "/saltboot"
	HealthEP                   = RootPath + "/health"
	ServerSaveEP               = RootPath + "/server/save"
	ServerDistributeEP         = RootPath + "/server/distribute"
	SaltActionDistributeEP     = RootPath + "/salt/action/distribute"
	SaltMinionEp               = RootPath + "/salt/minion"
	SaltMinionRunEP            = SaltMinionEp + "/run"
	SaltMinionStopEP           = SaltMinionEp + "/stop"
	SaltMinionKeyEP            = SaltMinionEp + "/fingerprint"
	SaltMinionKeyDistributeEP  = SaltMinionEp + "/fingerprint/distribute"
	SaltServerEp               = RootPath + "/salt/server"
	SaltServerRunEP            = SaltServerEp + "/run"
	SaltServerStopEP           = SaltServerEp + "/stop"
	SaltServerChangePasswordEP = SaltServerEp + "/change-password"
	SaltPillarEP               = RootPath + "/salt/server/pillar"
	SaltPillarDistributeEP     = RootPath + "/salt/server/pillar/distribute"
	HostnameDistributeEP       = RootPath + "/hostname/distribute"
	HostnameEP                 = RootPath + "/hostname"
	UploadEP                   = RootPath + "/file"
	FileDistributeEP           = UploadEP + "/distribute"
)

func NewCloudbreakBootstrapWeb() {
	log.Println("[web] NewCloudbreakBootstrapWeb")

	authenticator := Authenticator{}

	r := mux.NewRouter()
	r.HandleFunc(HealthEP, HealthCheckHandler).Methods("GET")
	r.Handle(ServerSaveEP, authenticator.Wrap(ServerRequestHandler, SIGNED)).Methods("POST")
	r.Handle(ServerDistributeEP, authenticator.Wrap(ClientDistributionHandler, SIGNED)).Methods("POST")

	r.Handle(SaltActionDistributeEP, authenticator.Wrap(SaltActionDistributeRequestHandler, SIGNED)).Methods("POST")

	r.Handle(SaltMinionRunEP, authenticator.Wrap(SaltMinionRunRequestHandler, SIGNED)).Methods("POST")
	r.Handle(SaltMinionStopEP, authenticator.Wrap(SaltMinionStopRequestHandler, SIGNED)).Methods("POST")
	r.Handle(SaltMinionKeyEP, authenticator.Wrap(SaltMinionKeyHandler, SIGNED)).Methods("POST")
	r.Handle(SaltMinionKeyDistributeEP, authenticator.Wrap(SaltMinionKeyDistributionHandler, SIGNED)).Methods("POST")

	r.Handle(SaltServerRunEP, authenticator.Wrap(SaltServerRunRequestHandler, SIGNED)).Methods("POST")
	r.Handle(SaltServerStopEP, authenticator.Wrap(SaltServerStopRequestHandler, SIGNED)).Methods("POST")
	r.Handle(SaltServerChangePasswordEP, authenticator.Wrap(SaltServerChangePasswordHandler, SIGNED)).Methods("POST")

	r.Handle(SaltPillarEP, authenticator.Wrap(SaltPillarRequestHandler, SIGNED)).Methods("POST")
	r.Handle(SaltPillarDistributeEP, authenticator.Wrap(SaltPillarDistributeRequestHandler, SIGNED)).Methods("POST")

	r.Handle(HostnameDistributeEP, authenticator.Wrap(ClientHostnameDistributionHandler, SIGNED)).Methods("POST")
	r.Handle(HostnameEP, authenticator.Wrap(ClientHostnameHandler, OPEN)).Methods("POST")

	r.Handle(UploadEP, authenticator.Wrap(FileUploadHandler, SIGNED)).Methods("POST")
	r.Handle(FileDistributeEP, authenticator.Wrap(FileUploadDistributeHandler, SIGNED)).Methods("POST")

	http.Handle("/", r)

	httpsEnabled := HttpsEnabled()
	httpsServerExit := make(chan bool)
	if httpsEnabled {
		go func() {
			httpsAddress := fmt.Sprintf(":%d", DetermineHttpsPort())
			httpsConfig := GetHttpsConfig()
			concCertFile, err := GetConcatenatedCertFilePath(httpsConfig)
			if err != nil {
				log.Printf("[web] Could not concatenate the server cert and ca cert: %v", err)
			} else {
				log.Printf("[web] starting server at address: %s", httpsAddress)
				if err = http.ListenAndServeTLS(httpsAddress, concCertFile, httpsConfig.KeyFile, nil); err != nil {
					log.Printf("[web] [ERROR] unable to ListenAndServeTLS: %s", err.Error())
				}
				httpsServerExit <- true
			}
		}()
	}

	httpAddress := fmt.Sprintf(":%d", DetermineHttpPort())
	log.Printf("[web] starting server at address: %s", httpAddress)
	if err := http.ListenAndServe(httpAddress, nil); err != nil {
		log.Printf("[web] [ERROR] unable to ListenAndServe: %s", err.Error())
	}

	if httpsEnabled {
		<-httpsServerExit
	}
}
