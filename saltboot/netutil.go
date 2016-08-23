package saltboot

import (
	"log"
	"os"
	"strconv"
	"strings"
)

func DetermineBootstrapPort() int {

	portStr := os.Getenv("SALTBOOT_PORT")
	log.Printf("[determineBootstrapPort] SALTBOOT_PORT: %s", portStr)
	port, err := strconv.Atoi(portStr)
	if err != nil {
		port = 7070
		log.Printf("[determineBootstrapPort] using default port: %d", port)
	}

	return port
}

func DetermineAuthCredentials() (string, string) {
	username := os.Getenv("SALTBOOT_USERNAME")
	password := os.Getenv("SALTBOOT_PASSWORD")
	log.Printf("[determineAuthCredentials] SALTBOOT_USERNAME: %s SALTBOOT_PASSWORD: %s", username, password)

	if len(strings.TrimSpace(username)) == 0 || len(strings.TrimSpace(password)) == 0 {
		username = "cbadmin"
		password = "cbadmin"
		log.Printf("[determineAuthCredentials] using default credentials, username: %s, password: %s", username, password)
	}
	return username, password
}
