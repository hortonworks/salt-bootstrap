package saltboot

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"github.com/hortonworks/salt-bootstrap/saltboot/model"
	"github.com/rafecolton/go-fileutils"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	logCollectDir        = "/tmp/cb-logs"
	logCollectAllHostDir = logCollectDir + "/all"
)

var defaultLogLocations = []string{
	"/var/log/salt/*",
	"/var/log/saltboot.log",
	"/var/log/user-data.log",
}

type LogRequest struct {
	LogLocations       []string    `json:"logLocations, omitempty"`
	AnonymizationRules interface{} `json:"anonymizationRules, omitempty"`
}

type LogRequestOnHosts struct {
	Targets    []string   `json:"targets,omitempty"`
	LogRequest LogRequest `json:"logRequest,omitempty"`
}

func CollectLogsFromAllHosts(writer http.ResponseWriter, req *http.Request) {
	log.Println("[CollectLogsFromHosts] collects logs")
	decoder := json.NewDecoder(req.Body)
	var logRequest LogRequestOnHosts
	err := decoder.Decode(&logRequest)
	if err != nil {
		log.Printf("[CollectLogsFromHosts] [ERROR] couldn't decode json: %s", err.Error())
		model.Response{Status: err.Error()}.WriteBadRequestHttp(writer)
		return
	}
	targets := logRequest.Targets
	log.Printf("[CollectLogsFromAllHosts] requested targets for log collection: %s", targets)
	user, pass := GetAuthUserPass(req)
	signature := strings.TrimSpace(req.Header.Get(SIGNATURE))
	archiveFile, err := CollectLogsFromHosts(targets, logRequest.LogRequest,
		LogCollectEP, user, pass, signature)
	if err != nil {
		http.Error(writer, err.Error(), 500)
		return
	}
	Openfile, err := os.Open(archiveFile)
	if err != nil {
		http.Error(writer, "File not found.", 404)
		return
	}
	defer closeIt(Openfile)
	FileContentType := "application/gzip"
	FileStat, _ := Openfile.Stat()
	FileSize := strconv.FormatInt(FileStat.Size(), 10)
	writer.Header().Set("Content-Disposition", "attachment; filename="+archiveFile)
	writer.Header().Set("Content-Type", FileContentType)
	writer.Header().Set("Content-Length", FileSize)
	if _, err = io.Copy(writer, Openfile); err != nil {
		log.Printf("[CollectLogsFromHosts] [ERROR] couldn't copy the file to the repsonse: %s", err.Error())
	}
}

func CollectLogs(writer http.ResponseWriter, req *http.Request) {
	log.Println("[CollectLogs] collects logs")
	var logRequest LogRequest
	decoder := json.NewDecoder(req.Body)
	err := decoder.Decode(&logRequest)
	if err != nil {
		log.Printf("[CollectLogs] [ERROR] couldn't decode json: %s", err.Error())
		model.Response{Status: err.Error()}.WriteBadRequestHttp(writer)
		return
	}
	logLocations := logRequest.LogLocations
	if logLocations == nil || len(logLocations) == 0 {
		logLocations = defaultLogLocations
	}
	anonymizationRules := logRequest.AnonymizationRules
	Filename, err := collectLogs(logLocations, anonymizationRules)
	if err != nil {
		http.Error(writer, err.Error(), 500)
		return
	}
	Openfile, err := os.Open(Filename)
	if err != nil {
		http.Error(writer, "File not found.", 404)
		return
	}
	defer closeIt(Openfile)
	FileContentType := "application/gzip"
	FileStat, _ := Openfile.Stat()
	FileSize := strconv.FormatInt(FileStat.Size(), 10)
	writer.Header().Set("Content-Disposition", "attachment; filename="+Filename)
	writer.Header().Set("Content-Type", FileContentType)
	writer.Header().Set("Content-Length", FileSize)
	if _, err = io.Copy(writer, Openfile); err != nil {
		log.Printf("[CollectLogs] [ERROR] couldn't copy the file to the repsonse: %s", err.Error())
	}
}

func CollectLogsFromHosts(clients []string, logRequest LogRequest,
	endpoint string, user string, pass string, signature string) (string, error) {
	var wg sync.WaitGroup
	wg.Add(len(clients))
	baseName := time.Now().Format("20060102_150405")
	destDir := filepath.Join(logCollectAllHostDir, baseName)
	if err := os.MkdirAll(destDir, os.ModeDir|os.ModePerm); err != nil {
		return "", err
	}
	jsonString, _ := json.Marshal(logRequest)
	var clientErr error
	for _, client := range clients {
		go func(client string) {
			defer wg.Done()
			log.Printf("[CollectLogsFromHosts] collect logs from: %s", client)

			var clientAddr string
			if strings.Contains(client, ":") {
				clientAddr = client
			} else {
				clientAddr = client + ":" + strconv.Itoa(DetermineBootstrapPort())
			}
			req, err := http.NewRequest("POST", "http://"+clientAddr+endpoint, bytes.NewBuffer(jsonString))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(SIGNATURE, signature)
			req.SetBasicAuth(user, pass)

			httpClient := &http.Client{}
			resp, err := httpClient.Do(req)
			if err != nil {
				log.Printf("[CollectLogsFromHosts] [ERROR] Failed to send logcollect request to: %s, error: %s", client, err.Error())
				clientErr = err
			}
			body, err := ioutil.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusOK {
				clientErr = errors.New(string(body))
			}
			if err != nil {
				log.Printf("[CollectLogsFromHosts] [ERROR] Failed to read response body from logcollect from: %s, error: %s", client, err.Error())
				clientErr = err
				return
			}
			destFile := destDir + "/" + client + ".tar.gz"
			err = ioutil.WriteFile(destFile, body, os.ModePerm)
			if err != nil {
				log.Printf("[CollectLogsFromHosts] [ERROR] Failed to write response body to file: %s, error: %s", destFile, err.Error())
				clientErr = err
			}
			defer closeIt(resp.Body)
		}(client)
	}
	wg.Wait()
	if clientErr != nil {
		return "", clientErr
	}
	archiveFile := filepath.Join(logCollectAllHostDir, baseName+"-logs-allhosts.tar.gz")
	err := archiveDirectory(destDir, archiveFile)
	if err != nil {
		return "", err
	}
	return archiveFile, nil
}

func collectLogs(logLocations []string, anonymizationRules interface{}) (string, error) {
	files, err := listFiles(logLocations)
	if err != nil {
		return "", err
	}
	destDir := filepath.Join(logCollectDir, time.Now().Format("2006-01-02_15:04:05"))
	err = os.MkdirAll(destDir, os.ModeDir|os.ModePerm)
	if err != nil {
		return "", err
	}
	err = collectLogFiles(files, destDir)
	if err != nil {
		return "", err
	}
	err = anonymize(destDir, anonymizationRules)
	if err != nil {
		return "", err
	}
	archiveFile := destDir + ".tar.gz"
	err = archiveDirectory(destDir, archiveFile)
	if err != nil {
		return "", err
	}
	return archiveFile, nil
}

func listFiles(patterns []string) (files []string, err error) {
	files, err = filepath.Glob(patterns[0])
	if err != nil {
		return nil, err
	}
	return files, nil
}

func collectLogFiles(files []string, destDir string) error {
	for _, file := range files {
		fileInfo, err := os.Stat(file)
		if err != nil {
			return err
		}
		err = fileutils.CpR(file, filepath.Join(destDir, fileInfo.Name()))
		if err != nil {
			return err
		}
	}
	return nil
}

func anonymize(directory string, anonymizationRules interface{}) error {
	return nil
}

func archiveDirectory(directory string, archive string) error {
	fileWriter, err := os.Create(archive)
	if err != nil {
		return err
	}
	defer closeIt(fileWriter)
	zipWriter := gzip.NewWriter(fileWriter)
	defer closeIt(zipWriter)
	tarWriter := tar.NewWriter(zipWriter)
	defer closeIt(tarWriter)
	err = filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		header, err := tar.FileInfoHeader(info, info.Name())
		if err != nil {
			return err
		}
		header.Name = strings.TrimPrefix(strings.Replace(path, directory, "", -1), string(filepath.Separator))
		if len(header.Name) == 0 {
			return nil
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		f, err := os.Open(path)
		defer closeIt(f)
		if err != nil {
			return err
		}
		if _, err := io.Copy(tarWriter, f); err != nil {
			return err
		}
		return nil
	})
	return err
}
