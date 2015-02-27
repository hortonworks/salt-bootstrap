package model

import "fmt"

type ConsulJoin struct {
    RetryJoin           []string    `json:"retry_join"`
    BootstrapExpect     int         `json:"bootstrap_expect,omitempty"`
    Server              bool        `json:"-"`
}


func (cj ConsulJoin) String() string {
    return fmt.Sprintf("ConsulJoin[RetryJoin: %s, BootstrapExpect: %d, Server: %t]", cj.RetryJoin, cj.BootstrapExpect, cj.Server)
}
