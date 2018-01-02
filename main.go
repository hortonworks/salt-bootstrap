package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/hortonworks/salt-bootstrap/saltboot"
)

func main() {
	if len(os.Args) > 1 && strings.HasSuffix(os.Args[1], "version") {
		fmt.Printf("Version: %s-%s", saltboot.Version, saltboot.BuildTime)
		return
	}

	logFile, err := os.OpenFile("/var/log/saltboot.log", os.O_APPEND|os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		log.Printf("Error opening log file: %s", err.Error())
	}
	defer func() {
		if err := logFile.Close(); err != nil {
			panic(err)
		}
	}()
	log.SetOutput(io.MultiWriter(os.Stdout, logFile))

	log.Println("[main] Launch salt-bootstrap application")
	log.Printf("[main] Version: %s-%s", saltboot.Version, saltboot.BuildTime)
	saltboot.NewCloudbreakBootstrapWeb()
}
