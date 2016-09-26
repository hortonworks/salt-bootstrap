package saltboot

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

type Authenticator struct {
	Username string
	Password string
}

func (a *Authenticator) Wrap(handler func(w http.ResponseWriter, req *http.Request), signatureKey []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		valid := CheckAuth(a.Username, a.Password, r)
		if !valid {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("401 Unauthorized"))
			return
		}
		if signatureKey != nil {
			body := new(bytes.Buffer)
			if strings.Index(r.Header.Get("Content-Type"), "multipart") == 0 {
				file, _, _ := r.FormFile("file")
				defer file.Close()
				ioutil.ReadAll(io.TeeReader(file, body))
			} else {
				defer r.Body.Close()
				ioutil.ReadAll(io.TeeReader(r.Body, body))
				r.Body = ioutil.NopCloser(body)
			}
			signature := strings.TrimSpace(r.Header.Get("signature"))
			if !CheckSignature(signature, signatureKey, body.Bytes()) {
				w.WriteHeader(http.StatusNotAcceptable)
				w.Write([]byte("406 Not Acceptable"))
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		http.HandlerFunc(handler).ServeHTTP(w, r)
	})
}

func CheckAuth(user string, pass string, r *http.Request) bool {
	hUser, hPassword := GetAuthUserPass(r)
	result := user == hUser && pass == hPassword
	if !result {
		log.Printf("[auth] invalid autorization header: %s from %s", r.Header.Get("Authorization"), r.Host)
	}
	return result
}

func CheckSignature(rawSign string, pubPem []byte, data []byte) bool {
	var err error
	var sign []byte
	var pub interface{}
	sign, err = base64.StdEncoding.DecodeString(rawSign)
	if err == nil {
		block, _ := pem.Decode(pubPem)
		if block != nil {
			pub, err = x509.ParsePKIXPublicKey(block.Bytes)
			if err == nil {
				newHash := crypto.SHA256.New()
				newHash.Write(data)
				opts := rsa.PSSOptions{SaltLength: 20}
				err = rsa.VerifyPSS(pub.(*rsa.PublicKey), crypto.SHA256, newHash.Sum(nil), sign, &opts)
				if err == nil {
					return true
				}
			}
		} else {
			err = errors.New("unable to decode PEM")
		}
	}
	log.Printf("[auth] unable to check signature: %s", err)

	return false
}

func GetAuthUserPass(r *http.Request) (string, string) {
	s := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(s) != 2 || s[0] != "Basic" {
		log.Printf("[auth] Missing Basic authorization header")
		return "", ""
	}
	b, err := base64.StdEncoding.DecodeString(s[1])
	if err != nil {
		log.Printf("[auth] Authorization header is not MD5 encoded: %s", err.Error())
		return "", ""
	}
	pair := strings.Split(string(b), ":")
	if len(pair) != 2 {
		log.Printf("[auth] Missing username/password")
		return "", ""
	}
	return pair[0], pair[1]
}
