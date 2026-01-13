package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
)

type Service struct {
	Client         *http.Client
	Token          string
	Debug          bool
	PredicateTypes []string
}

const (
	apiVersion = "externaldata.gatekeeper.sh/v1alpha1"
)

// Evidence GraphQL request structures.
type EvidenceRequest struct {
	Query string `json:"query"`
}

type EvidenceResponse struct {
	Data EvidenceData `json:"data"`
}

type EvidenceData struct {
	Evidence EvidenceWrapper `json:"evidence"`
}

type EvidenceWrapper struct {
	SearchEvidence EvidenceSearch `json:"searchEvidence"`
}

type EvidenceSearch struct {
	Edges []EvidenceEdge `json:"edges"`
}

type EvidenceEdge struct {
	Node EvidenceNode `json:"node"`
}

type EvidenceNode struct {
	DownloadPath  string          `json:"downloadPath"`
	Path          string          `json:"path"`
	Name          string          `json:"name"`
	Sha256        string          `json:"sha256"`
	Subject       EvidenceSubject `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
	CreatedBy     string          `json:"createdBy"`
	CreatedAt     string          `json:"createdAt"`
	Verified      bool            `json:"verified"`
}

type EvidenceSubject struct {
	RepositoryKey string `json:"repositoryKey"`
	Path          string `json:"path"`
	Name          string `json:"name"`
}

func main() {
	// make sure JFROG_TOKEN_SECRET exists
	tokenSecret := os.Getenv("JFROG_TOKEN_SECRET")
	if tokenSecret == "" {
		log.Fatalf("JFROG_TOKEN_SECRET is not set, make sure to create kubernetes secret called jfrog-token-secret with a JFrog access token as the value")
	}

	addr := flag.String("addr", ":8443", "listen address for HTTPS")
	fmt.Printf("starting provider on %s (TLS)\n", *addr)
	flag.Parse()

	http.HandleFunc("/", providerHandler)
	caCert, err := os.ReadFile("/tmp/gatekeeper/ca.crt")
	clientCAs := x509.NewCertPool()
	clientCAs.AppendCertsFromPEM(caCert)

	if err != nil {
		panic(err)
	}
	srv := &http.Server{
		Addr:              ":8443",
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  clientCAs,
			MinVersion: tls.VersionTLS13,
		},
	}

	if err := srv.ListenAndServeTLS("/tmp/jfrog/server.crt", "/tmp/jfrog/server.key"); err != nil {
		log.Fatalf("server exited: %v", err)
	}
}

func (s *Service) getEvidence(registry string, repository string, image string, tag string, digest string) (bool, error) {
	// call api to get evidence
	// call api with the format of https://apptrustswampupb.jfrog.io/onemodel/api/v1/graphql
	url := fmt.Sprintf("https://%s/onemodel/api/v1/graphql", registry)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+s.Token)
	req.Header.Set("Content-Type", "application/json")
	evidenceRequest := EvidenceRequest{
		Query: fmt.Sprintf("{ evidence { searchEvidence(where: { hasSubjectWith: { repositoryKey: \"%s\", path: \"%s/%s\", sha256: \"%s\" } }) { edges { node { downloadPath path name sha256 subject { repositoryKey path name } predicateType predicate createdBy createdAt verified } } } }}", repository, image, tag, digest),
	}
	jsonRequest, err := json.Marshal(evidenceRequest)
	if err != nil {
		return false, err
	}
	req.Body = io.NopCloser(bytes.NewBuffer(jsonRequest))
	if s.Debug {
		fmt.Println("evidence request:", req.Body)
	}
	response, err := s.Client.Do(req)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()
	if s.Debug {
		fmt.Println("evidence response status:", response.StatusCode)
	}
	if response.StatusCode != 200 {
		return false, fmt.Errorf("failed to get evidence, response status: %s", response.Status)
	}
	// read response body
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return false, err
	}
	if s.Debug {
		fmt.Println("body:", string(body))
	}
	// unmarshal body into EvidenceResponse
	var evidenceResponse EvidenceResponse
	err = json.Unmarshal(body, &evidenceResponse)
	if err != nil {
		fmt.Println("error unmarshalling evidence response:", err)
		return false, fmt.Errorf("error unmarshalling evidence response: %v", err)
	}
	if s.Debug {
		fmt.Println("evidence graphQL Response:", evidenceResponse)
	}

	// check we have edges
	if len(evidenceResponse.Data.Evidence.SearchEvidence.Edges) == 0 {
		return false, fmt.Errorf("no evidence found")
	}

	// check if we have evidence of predicateType
	for _, predicateType := range s.PredicateTypes {
		//for all PredicateTypes check if we have evidence and if it is verified
		typeFound := false
		for _, edge := range evidenceResponse.Data.Evidence.SearchEvidence.Edges {
			if edge.Node.PredicateType == predicateType && edge.Node.Verified {
				fmt.Println("evidence found and verified for", edge.Node.PredicateType)
				typeFound = true
				break
			}
		}
		if !typeFound {
			return false, fmt.Errorf("no evidence found for predicate type %s", predicateType)
		}
	}
	return true, nil
}

func (s *Service) getJFrogImageInfo(registry string, repository string, image string, tag string) (string, error) {
	// call jfrog api to get the digest
	// call api with the format of https:/{registry}/artifactory/api/docker/{repository}/v2/{image}/manifests/{tag}
	// extract tag by splitting :

	url := fmt.Sprintf("https://%s/artifactory/api/docker/%s/v2/%s/manifests/%s", registry, repository, image, tag)
	if s.Debug {
		fmt.Println("url:", url)
	}

	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+s.Token)
	req.Header.Set("Accept", "application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.manifest.v1+json")

	response, err := s.Client.Do(req)
	if err != nil {
		return "", err
	}
	if s.Debug {
		fmt.Println("jfrog image info response:", response)
	}
	if response.StatusCode != 200 {
		return "", fmt.Errorf("failed to get digest, response status: %s", response.Status)
	}
	//get digest from response X-Checksum-Sha256 header
	// if Docker-Content-Digest header is present, use it instead of X-Checksum-Sha256
	digest := response.Header.Get("Docker-Content-Digest")
	if digest == "" {
		digest = response.Header.Get("X-Checksum-Sha256")
	}
	// remove sha256: prefix if present
	digest = strings.TrimPrefix(digest, "sha256:")

	if s.Debug {
		fmt.Println("digest:", digest)
	}

	if digest == "" {
		return "", fmt.Errorf("failed to get digest from header, response status: %s", response.Status)
	}
	return digest, nil
}

func providerHandler(w http.ResponseWriter, req *http.Request) {
	fmt.Println("in providerHandler ")
	// initializations
	// Add a reusable HTTP client
	var client = &http.Client{
		Timeout: 4 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:       100,
			IdleConnTimeout:    10 * time.Second,
			DisableCompression: true,
		},
	}
	debug := os.Getenv("DEBUG") == "true"
	if debug {
		fmt.Println("debug mode is enabled")
	}

	svc := NewService(client, "", debug)
	tokenSecret := os.Getenv("JFROG_TOKEN_SECRET")
	if tokenSecret == "" {
		svc.sendResponse(nil, "JFROG_TOKEN_SECRET is not set, make sure to create kubernetes secret called jfrog-token-secret with a JFrog access token as the value", w)
		return
	}
	svc.Token = tokenSecret

	// only accept POST requests
	if req.Method != http.MethodPost {
		svc.sendResponse(nil, "only POST is allowed", w)
		return
	}

	// read request body
	requestBody, err := io.ReadAll(req.Body)
	if err != nil {
		svc.sendResponse(nil, fmt.Sprintf("unable to read request body: %v", err), w)
		return
	}
	// parse request body
	var providerRequest externaldata.ProviderRequest
	err = json.Unmarshal(requestBody, &providerRequest)
	if err != nil {
		svc.sendResponse(nil, fmt.Sprintf("unable to unmarshal request body: %v", err), w)
		return
	}
	fmt.Println("request keys:", providerRequest.Request.Keys)

	results := make([]externaldata.Item, 0)
	// iterate over all keys
	predicateTypesString := providerRequest.Request.Keys[0]
	if debug {
		fmt.Println("predicate types:", predicateTypesString)
	}
	if predicateTypesString == "" {
		svc.sendResponse(nil, "predicate type is not set", w)
		return
	}
	// split predicateType into array
	predicateTypes := strings.Split(predicateTypesString, ",")
	svc.PredicateTypes = predicateTypes
	if svc.Debug {
		fmt.Println("predicate types:", svc.PredicateTypes)
	}
	if len(providerRequest.Request.Keys) == 1 {
		fmt.Println("no images to check")
		svc.sendResponse(nil, "", w)
		return
	}

	for _, key := range providerRequest.Request.Keys[1:] { // skip the first key which is the predicate type
		if svc.Debug {
			fmt.Println("Getting digest for:", key)
		}
		// do something with the key
		// call jfrog api to get the digest
		registry, repository, image, tag, err := svc.SplitImageKey(key)
		if err != nil {
			svc.sendResponse(nil, fmt.Sprintf("unable to split image key for %s: %v", key, err), w)
			return
		}

		digest, err := svc.getJFrogImageInfo(registry, repository, image, tag)
		if err != nil {
			svc.sendResponse(nil, fmt.Sprintf("unable to get digest for %s: %v", key, err), w)
			return
		}
		// check if evidence exists
		evidenceExists, err := svc.getEvidence(registry, repository, image, tag, digest)

		if evidenceExists {
			fmt.Println("evidence found and verified for", key)
			results = append(results, externaldata.Item{
				Key:   key,
				Value: "_valid",
			})
		} else {
			fmt.Println("evidence not found for", key)
			results = append(results, externaldata.Item{
				Key:   key,
				Value: "_invalid",
			})
		}
	}

	svc.sendResponse(&results, "", w)
}

// sendResponse sends back the response to Gatekeeper.
func (s *Service) sendResponse(results *[]externaldata.Item, systemErr string, w http.ResponseWriter) {
	response := externaldata.ProviderResponse{
		APIVersion: apiVersion,
		Kind:       "ProviderResponse",
	}

	if results != nil {
		response.Response.Items = *results
	} else {
		response.Response.SystemError = systemErr
	}
	if s.Debug {
		// print out json response as pretty string
		jsonResponse, err := json.MarshalIndent(response, "", "  ")
		if err != nil {
			fmt.Println("error marshalling response:", err)
			return
		}
		fmt.Println("response:", string(jsonResponse))
	}
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		panic(err)
	}
}

func (s *Service) SplitImageKey(key string) (string, string, string, string, error) {
	tagParts := strings.Split(key, ":")
	if len(tagParts) != 2 {
		return "", "", "", "", fmt.Errorf("key %q missing tag separator ':'", key)
	}
	tag := tagParts[1]
	imageAddress := tagParts[0]

	parts := strings.Split(imageAddress, "/")
	if len(parts) < 3 {
		return "", "", "", "", fmt.Errorf("key %q missing registry/repository/image parts", key)
	}

	registry := parts[0]
	repository := parts[1]
	image := strings.Join(parts[2:], "/")

	if s.Debug {
		fmt.Println("registry:", registry, "repository:", repository, "image:", image, "tag:", tag)
	}

	return registry, repository, image, tag, nil
}
func NewService(client *http.Client, token string, debug bool) *Service {
	return &Service{
		Client: client,
		Token:  token,
		Debug:  debug,
	}
}
