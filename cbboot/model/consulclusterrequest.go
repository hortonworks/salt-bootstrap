package model

import "fmt"


type ConsulClusterRequest struct {
    //will be used for swarm
    Target           string            `json:"target,omitempty"`
    Image            string            `json:"image"`
    ServerCount      int               `json:"serverCount"`
    ConsulBootstraps []ConsulBootstrap `json:"consulBootstraps"`

}

func (r ConsulClusterRequest) String() string {
    return fmt.Sprintf("ConsulClusterRequest[Target: %s, Image: %s, ServerCount: %d, ConsulBootstraps %s]", r.Target, r.Image, r.ServerCount, r.ConsulBootstraps)
}
