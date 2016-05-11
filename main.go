package main

import (
    "fmt"
    "log"
    "os"
    "strings"
    "github.com/sequenceiq/salt-bootstrap/saltboot"
)

func main() {
    if len(os.Args) > 1 && strings.HasSuffix(os.Args[1], "version") {
        fmt.Printf("Version: %s-%s", saltboot.Version, saltboot.BuildTime)
        return
    }
    log.Println("[main] Launch salt-bootstrap application")
    saltboot.NewCloudbreakBootstrapWeb()
}
