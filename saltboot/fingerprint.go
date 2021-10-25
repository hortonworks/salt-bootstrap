package saltboot

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/hortonworks/salt-bootstrap/saltboot/model"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

const (
	MinionKey    = "/etc/salt/pki/minion/minion.pem"
	SaltLocation = "/opt/"
)

type FingerprintsRequest struct {
	Minions []SaltMinion `json:"minions,omitempty"`
}

type FingerprintsResponse struct {
	Fingerprints []Fingerprint `json:"fingerprints"`
	ErrorText    *string       `json:"errorText"`
	StatusCode   int           `json:"statusCode"`
}

func (r FingerprintsResponse) WriteBadRequestHttp(w http.ResponseWriter, err error) FingerprintsResponse {
	w.WriteHeader(http.StatusBadRequest)
	r.StatusCode = http.StatusBadRequest
	r.ErrorText = convertToNilIfEmpty(err.Error())
	return EncodeResponseJson(r, w)
}

func (r FingerprintsResponse) String() string {
	j, _ := json.Marshal(r)
	return fmt.Sprintf("FingerprintsResponse: %s", string(j))
}

func EncodeResponseJson(r FingerprintsResponse, w http.ResponseWriter) FingerprintsResponse {
	err := json.NewEncoder(w).Encode(r)
	if err != nil {
		log.Printf("[EncodeResponseJson] [ERROR] failed to create json from FingerprintsResponse: %s", err.Error())
	}
	return r
}

type Fingerprint struct {
	Fingerprint *string `json:"fingerprint"`
	ErrorText   *string `json:"errorText"`
	StatusCode  int     `json:"statusCode"`
	Address     string  `json:"address"`
}

func (k Fingerprint) WriteHttp(w http.ResponseWriter) Fingerprint {
	if k.StatusCode == 0 {
		k.StatusCode = 200
	}
	w.WriteHeader(k.StatusCode)
	return EncodeJson(k, w)
}

func (r Fingerprint) String() string {
	j, _ := json.Marshal(r)
	return fmt.Sprintf("Fingerprint: %s", string(j))
}

func EncodeJson(k Fingerprint, w http.ResponseWriter) Fingerprint {
	err := json.NewEncoder(w).Encode(k)
	if err != nil {
		log.Printf("[writehttp] [ERROR] failed to create json from model: %s", err.Error())
	}
	return k
}

func newFingerprint(response model.Response) Fingerprint {
	return Fingerprint{
		StatusCode:  response.StatusCode,
		ErrorText:   convertToNilIfEmpty(response.ErrorText),
		Address:     response.Address,
		Fingerprint: convertToNilIfEmpty(response.Status),
	}
}

func convertToNilIfEmpty(value string) *string {
	if len(value) == 0 {
		return nil
	}
	return &value
}

func (r FingerprintsRequest) distributeRequest(user string, pass string, signedRequestBody RequestBody) []Fingerprint {
	log.Print("[distributeRequest] distribute fingerprint request to targets")
	return distributeFingerprintImpl(DistributeRequest, r, user, pass, signedRequestBody)
}

func distributeFingerprintImpl(distributeRequest func([]string, string, string, string, RequestBody) <-chan model.Response,
	request FingerprintsRequest, user string, pass string, requestBody RequestBody) (result []Fingerprint) {

	var targets []string
	for _, minion := range request.Minions {
		targets = append(targets, minion.Address)
	}

	log.Printf("[distributeFingerprintImpl] send fingerprint request to minions: %s", targets)
	for res := range distributeRequest(targets, SaltMinionKeyEP, user, pass, requestBody) {
		result = append(result, newFingerprint(res))
	}

	return result
}

func getMinionFingerprintFromPrivateKey() model.Response {
	keyLocation := MinionKey
	log.Println("[getMinionFingerprintFromPrivateKey] generate the fingerprint from the minion's private key: " + keyLocation)

	privateKeyText, err := ioutil.ReadFile(keyLocation)
	if err != nil {
		return createErrorResponse(fmt.Sprintf("unable to load file %s", keyLocation), err)
	}

	privateKeyPem, _ := pem.Decode(privateKeyText)
	if privateKeyPem == nil {
		return createErrorResponse("Invalid key", errors.New("cannot decode private key"))
	}

	privateKeyDer, err := x509.ParsePKCS1PrivateKey(privateKeyPem.Bytes)
	if err != nil {
		return createErrorResponse("cannot parse private key to DER format", err)
	}

	publicKeyDer, err := x509.MarshalPKIXPublicKey(&privateKeyDer.PublicKey)
	if err != nil {
		return createErrorResponse("cannot marshal to public key", err)
	}

	pubKeyBlock := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDer,
	}

	publicKeyPem := string(pem.EncodeToMemory(&pubKeyBlock))
	log.Printf("[getMinionFingerprintFromPrivateKey] public key in PEM format \n%s", publicKeyPem)

	fingerprint := getFingerprint(publicKeyPem)
	log.Printf("[getMinionFingerprintFromPrivateKey] calculated fiingerprint: %s", fingerprint)

	return model.Response{Status: fingerprint}
}

func getFingerprint(publicKey string) string {
	publicKeyWithoutFirstLine := strings.Replace(publicKey, "-----BEGIN PUBLIC KEY-----\n", "", 1)
	publicKeyWithoutFirstAndLastLine := strings.Replace(publicKeyWithoutFirstLine, "-----END PUBLIC KEY-----\n", "", 1)
	hasher := sha256.New()
	io.WriteString(hasher, publicKeyWithoutFirstAndLastLine)
	sum := hasher.Sum(nil)
	fingerprint := ""
	for i, b := range sum {
		fingerprint += fmt.Sprintf("%02x", b)
		if i < len(sum)-1 {
			fingerprint += ":"
		}
	}
	return fingerprint
}

func createErrorResponse(message string, err error) model.Response {
	errorMessage := fmt.Sprintf("%s, err: %s", message, err.Error())
	log.Printf("[getMinionFingerprintFromPrivateKey] [ERROR] %s", message)
	return model.Response{
		StatusCode: http.StatusInternalServerError,
		ErrorText:  errorMessage,
	}
}
