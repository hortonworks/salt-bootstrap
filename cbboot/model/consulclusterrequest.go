package model

import "fmt"


type ConsulClusterRequest struct {
    //will be used for swarm
    Distribute       bool              `json:"distribute"`
    //will be used for swarm
    Target           string            `json:"target"`
    Image            string            `json:"image"`
    ServerCount      int               `json:"serverCount"`
    ConsulBootstraps []ConsulBootstrap `json:"consulBootstraps"`

}

func (r ConsulClusterRequest) String() string {
    return fmt.Sprintf("ConsulClusterRequest[Distribute: %t, Target: %s, Image: %s, ServerCount: %d, ConsulBootstraps %s]", r.Distribute, r.Target, r.Image, r.ServerCount, r.ConsulBootstraps)
}
