package model

import "fmt"

type ConsulBootstrap struct {
    Address           string    `json:"address"`
    Server            bool      `json:"server"`
}


func (r ConsulBootstrap) String() string {
    return fmt.Sprintf("ConsulBootstrap[Address: %s, Server: %t]", r.Address, r.Server)
}
