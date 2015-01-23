package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/sequenceiq/cloudbreak-bootstrap/cbboot"
)

func main() {

	if len(os.Args) > 1 && strings.HasSuffix(os.Args[1], "version") {
		fmt.Println("Version: ", cbboot.Version)
		return
	}

	log.Println("[main] Launch cloudbreak-bootstrap")

	cbboot.NewCloudbreakBootstrapWeb()

}
