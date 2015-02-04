package cbboot

import (
    "log"
    "os"
    "io/ioutil"
    "github.com/samalba/dockerclient"
    "crypto/tls"
    "path/filepath"
    "crypto/x509")


func config() (*dockerclient.DockerClient, error) {

    dockerHost := os.Getenv("DOCKER_HOST")
    if dockerHost == "" {
        dockerHost = "unix:///var/run/docker.sock"
    }
    log.Println("dockerHost: ", dockerHost)

    prefixCertPath := os.Getenv("DOCKER_CERT_PATH")
    log.Println("prefixCertPath: ", prefixCertPath)

    var tlsConfig *tls.Config
    clientCert, err := tls.LoadX509KeyPair(
    filepath.Join(prefixCertPath, "cert.pem"),
    filepath.Join(prefixCertPath, "key.pem"),
    )
    if err != nil {
        log.Fatal("LoadX509KeyPair: ", err)
    } else {
        log.Println(" [client] LoadX509KeyPair executed successfully")
    }

    rootCAs := x509.NewCertPool()
    log.Println(" [client] x509.NewCertPool() executed successfully")

    caCert, err := ioutil.ReadFile(filepath.Join(prefixCertPath, "ca.pem"))
    if err != nil {
        log.Fatal("ioutil.ReadFile: ", err)
    } else {
        log.Println(" [client] ca.pem loaded successfully")
    }
    rootCAs.AppendCertsFromPEM(caCert)
    log.Println(" [client] AppendCertsFromPEM created")

    tlsConfig = &tls.Config{
        Certificates: []tls.Certificate{clientCert},
        RootCAs:      rootCAs,
    }

    log.Println(" [client] tlsConfig created")

    return dockerclient.NewDockerClient(dockerHost, tlsConfig)
}

func execute(c Container) (err error) {
    docker, err := config();
    if err != nil {
        log.Fatal(" [client] failed to connect to Docker Deamon", err)
        return err
    } else {
        log.Println(" [client] docker client created")
    }

    // Create a container
    containerConfig := &dockerclient.ContainerConfig{Image: "ubuntu", Cmd: []string{"/bin/bash"}}
    log.Println(" [client] ContainerConfig created successfully")
    containerId, err := docker.CreateContainer(containerConfig, "some_name")
    if err != nil {
        log.Fatal("Failed to create Container: ", err)
        return err
    } else {
        log.Println(" [client] CreateContainer created with id: ", containerId)
    }
    // Start the container
    err = docker.StartContainer(containerId, &containerConfig.HostConfig)
    if err != nil {
        log.Fatal(err)
        return err
    }
    log.Println(" [client] SUCCESS. Container Launched with ID: ", containerId)
    return nil
}
