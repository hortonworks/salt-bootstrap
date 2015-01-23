package cbboot

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
)

func launchContainer(w http.ResponseWriter, req *http.Request) {
	log.Println("[web] launchContainer")

	decoder := json.NewDecoder(req.Body)
	var dc Container
	err := decoder.Decode(&dc)
	if err != nil {
		log.Fatal("[web] [ERROR] couldn't decode json: ", err)
		return
	}

	err = execute(dc);

	if err != nil {
		log.Fatal("[web] [ERROR] cannot start cocontainer: ", err)
		return
	}

}



func NewCloudbreakBootstrapWeb() {

	address := ":9090"

	port := os.Getenv("CBBOOT_PORT")
	if port != "" {
		address = fmt.Sprintf(":%s", port)
	}
	log.Println("[web] NewCloudbreakBootstrapWeb")

	r := mux.NewRouter()
	r.HandleFunc("/cbboot/launch", launchContainer).Methods("POST")

	log.Println("[web] starting server at:", address)
	http.Handle("/", r)
	http.ListenAndServe(address, nil)
}
