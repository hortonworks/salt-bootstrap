package saltboot

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/hortonworks/salt-bootstrap/saltboot/model"
)

func FileUploadDistributeHandler(w http.ResponseWriter, req *http.Request) {
	log.Println("[FileUploadDistributeHandler] execute file distribute")

	targets := req.FormValue("targets")
	log.Printf("[FileUploadDistributeHandler] requested targets for file distribute: %s", targets)
	path := req.FormValue("path")
	permissions := req.FormValue("permissions")
	file, header, err := req.FormFile("file")
	if err != nil {
		log.Printf("[FileUploadDistributeHandler] [ERROR] form file error: %s", err.Error())
		resp := model.Responses{Responses: []model.Response{{Status: err.Error(), StatusCode: http.StatusBadRequest}}}
		w.WriteHeader(http.StatusBadRequest)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("[FileUploadDistributeHandler] [ERROR] failed to encode resp: %s", err.Error())
		}
		return
	}

	user, pass := GetAuthUserPass(req)
	signature := strings.TrimSpace(req.Header.Get(SIGNATURE))

	result := fileDistributeActionImpl(user, pass, strings.Split(targets, ","), path, permissions, file, header, signature)
	cResp := model.Responses{Responses: result}
	log.Printf("[FileUploadDistributeHandler] distribute file upload request executed: %s", cResp.String())
	if err := json.NewEncoder(w).Encode(cResp); err != nil {
		log.Printf("[FileUploadDistributeHandler] [ERROR] failed to encode cResp: %s", err.Error())
	}
}

func fileDistributeActionImpl(user string, pass string, targets []string, path string, permissions string,
	file multipart.File, header *multipart.FileHeader, signature string) (result []model.Response) {
	for res := range DistributeFileUploadRequest(UploadEP, user, pass, targets, path, permissions, file, header, signature) {
		result = append(result, res)
	}
	return result
}

func FileUploadHandler(w http.ResponseWriter, req *http.Request) {
	log.Println("[FileUploadHandler] execute file upload")

	w.Header().Set("Content-Type", "text/plain")

	path := req.FormValue("path")
	log.Println("[FileUploadHandler] path: " + path)

	file, header, err := req.FormFile("file")
	if err != nil {
		log.Printf("[FileUploadHandler] [ERROR] form file error: %s", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		if _, err := w.Write([]byte("400 Bad Request")); err != nil {
			log.Printf("[FileUploadHandler] [ERROR] couldn't write response: %s", err.Error())
		}
		fmt.Fprintln(w, err)
		return
	}

	b, _ := io.ReadAll(file)

	if err := os.MkdirAll(path, 0744); err != nil {
		log.Printf("[FileUploadHandler] [ERROR] make dir error: %s", err.Error())
		w.WriteHeader(http.StatusForbidden)
		if _, err := w.Write([]byte("403 Forbidden")); err != nil {
			log.Printf("[FileUploadHandler] [ERROR] couldn't write response: %s", err.Error())
		}
		fmt.Fprintln(w, err)
		return
	}

	permissions := os.FileMode(0644)
	requestedPermissions := req.FormValue("permissions")
	if len(requestedPermissions) > 0 {
		log.Printf("[FileUploadHandler] requested special permissions: %s", requestedPermissions)
		perm64, _ := strconv.ParseUint(requestedPermissions, 8, 32)
		permissions = os.FileMode(perm64)
	}
	log.Printf("[FileUploadHandler] permissions to create the file with: %o", permissions)

	if strings.Contains(header.Filename, ".zip") {
		log.Println("[FileUploadHandler] unzip file from /tmp")
		if err := WriteFile("/tmp/"+header.Filename, b, permissions); err != nil {
			log.Printf("[FileUploadHandler] [ERROR] unable to write file: %s", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			if _, err := w.Write([]byte("500 Internal Server Error")); err != nil {
				log.Printf("[FileUploadHandler] [ERROR] couldn't write response: %s", err.Error())
			}
			fmt.Fprintln(w, err)
			return
		}
		if err := Unzip("/tmp/"+header.Filename, path); err != nil {
			log.Printf("[FileUploadHandler] [ERROR] unzipt file error: %s", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			if _, err := w.Write([]byte("500 Internal Server Error")); err != nil {
				log.Printf("[FileUploadHandler] [ERROR] couldn't write response: %s", err.Error())
			}
			fmt.Fprintln(w, err)
			return
		}
	} else {
		log.Println("[FileUploadHandler] FileName: " + header.Filename)
		if err := WriteFile(path+"/"+header.Filename, b, permissions); err != nil {
			log.Printf("[fileUploadHandler] [ERROR] wirte file error: %s", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			if _, err := w.Write([]byte("500 Internal Server Error")); err != nil {
				log.Printf("[FileUploadHandler] [ERROR] couldn't write response: %s", err.Error())
			}
			fmt.Fprintln(w, err)
			return
		}
	}

	defer closeIt(file)
	w.WriteHeader(http.StatusCreated)
	if _, err := w.Write([]byte("201 Created ")); err != nil {
		log.Printf("[FileUploadHandler] [ERROR] couldn't write response: %s", err.Error())
	}
	fmt.Fprintf(w, "File %s uploaded successfully.", header.Filename)
}
