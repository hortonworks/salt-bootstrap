package cbboot

import "fmt"

type Container struct {
	Name    string   `json:"name"`
	Image   string   `json:"image"`
	Volumes []string `json:"volumes"`
	EnvVars []string `json:"envVars"`
	Host    string   `json:"host"`
}

func (c Container) String() string {
	return fmt.Sprintf("Container[Name: %s, Image: %s, Volumes: %s, EnvVars: %s, Host: %s]", c.Name, c.Image, c.Volumes, c.EnvVars, c.Host)
}
