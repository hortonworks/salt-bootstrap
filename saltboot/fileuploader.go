package saltboot

import (
	"encoding/json"
	"fmt"
	"github.com/hortonworks/salt-bootstrap/saltboot/model"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"strconv"
	"strings"
)

func FileUploadDistributeHandler(w http.ResponseWriter, req *http.Request) {
	log.Println("[FileUploadDistributeHandler] execute file distribute")

	targets := req.FormValue("targets")
	log.Printf("[FileUploadDistributeHandler] requested targets for file distribute: %s", targets)
	path := req.FormValue("path")
	permissions := req.FormValue("permissions")
	file, header, err := req.FormFile("file")
	if err != nil {
		log.Printf("[FileUploadDistributeHandler] form file error: " + err.Error())
		resp := model.Responses{Responses: []model.Response{{Status: err.Error(), StatusCode: http.StatusBadRequest}}}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(resp)
		return
	}

	user, pass := GetAuthUserPass(req)
	signature := strings.TrimSpace(req.Header.Get(SIGNATURE))

	result := fileDistributeActionImpl(user, pass, strings.Split(targets, ","), path, permissions, file, header, signature)
	cResp := model.Responses{Responses: result}
	log.Printf("[FileUploadDistributeHandler] distribute file upload request executed: %s", cResp.String())
	json.NewEncoder(w).Encode(cResp)
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
	log.Printf("[FileUploadHandler] path: " + path)

	file, header, err := req.FormFile("file")
	if err != nil {
		log.Printf("[FileUploadHandler] form file error: " + err.Error())
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("400 Bad Request"))
		fmt.Fprintln(w, err)
		return
	}

	b, _ := ioutil.ReadAll(file)

	err = os.MkdirAll(path, 0744)
	if err != nil {
		log.Printf("[FileUploadHandler] make dir error: " + err.Error())
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("403 Forbidden"))
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
		ioutil.WriteFile("/tmp/"+header.Filename, b, permissions)
		err = Unzip("/tmp/"+header.Filename, path)
		if err != nil {
			log.Printf("[FileUploadHandler] unzipt file error: " + err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("500 Internal Server Error"))
			fmt.Fprintln(w, err)
			return
		}
	} else {
		log.Printf("[FileUploadHandler] FileName: " + header.Filename)
		err = ioutil.WriteFile(path+"/"+header.Filename, b, permissions)
		if err != nil {
			log.Printf("[fileUploadHandler] wirte file error: " + err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("500 Internal Server Error"))
			fmt.Fprintln(w, err)
			return
		}
	}

	defer file.Close()
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("201 Created "))
	fmt.Fprintf(w, "File %s uploaded successfully.", header.Filename)
}
