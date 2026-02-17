// (c) 2026 JFrog Ltd.
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

	"github.com/jmespath/go-jmespath"
	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
)

type Service struct {
	Client         *http.Client
	Token          string
	Debug          bool
	PredicateTypes []string
	ContentChecks  map[string][]string // predicate type -> JMESPath expressions
}

const (
	apiVersion             = "externaldata.gatekeeper.sh/v1alpha1"
	contentChecksConfigMap = "jfrog-provider-content-checks"
	k8sTokenPath           = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	k8sNamespacePath       = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
	k8sCACertPath          = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

// k8sConfigMap mirrors the relevant fields of a Kubernetes ConfigMap response.
type k8sConfigMap struct {
	Data map[string]string `json:"data"`
}

// Package-level content checks loaded once at provider startup.
var contentChecks map[string][]string

// Package-level HTTP client for connection reuse across requests
var httpClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
	},
}

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

	// Load optional content checks from Kubernetes ConfigMap at startup
	contentChecks = loadContentChecksFromConfigMap()

	addr := flag.String("addr", ":8443", "listen address for HTTPS")
	fmt.Printf("starting provider on %s (TLS)\n", *addr)
	flag.Parse()

	http.HandleFunc("/", providerHandler)

	// Read Gatekeeper CA certificate for mutual TLS
	caCert, err := os.ReadFile("/tmp/gatekeeper/ca.crt")
	if err != nil {
		log.Fatalf("failed to read Gatekeeper CA certificate: %v", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caCert) {
		log.Fatalf("failed to parse Gatekeeper CA certificate")
	}

	srv := &http.Server{
		Addr:              *addr,
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
	/*if s.Debug {
		fmt.Println("evidence graphQL Response:", evidenceResponse)
	}*/

	// check we have edges
	if len(evidenceResponse.Data.Evidence.SearchEvidence.Edges) == 0 {
		return false, fmt.Errorf("no evidence found")
	} else {
		fmt.Println(len(evidenceResponse.Data.Evidence.SearchEvidence.Edges), "evidence found")
	}

	// check if we have evidence of predicateType
	for _, predicateType := range s.PredicateTypes {
		//for all PredicateTypes check if we have evidence and if it is verified
		typeFound := false
		for _, edge := range evidenceResponse.Data.Evidence.SearchEvidence.Edges {
			if edge.Node.PredicateType == predicateType && edge.Node.Verified {
				// If JMESPath content checks exist for this predicate type, evaluate all of them
				if exprs, ok := s.ContentChecks[predicateType]; ok && len(exprs) > 0 {
					allPassed := true
					for _, expr := range exprs {
						if err := s.validateEdidenceContent(edge.Node, expr); err != nil {
							if s.Debug {
								fmt.Printf("content check failed for %s: %v\n", predicateType, err)
							}
							allPassed = false
							break
						}
					}
					if !allPassed {
						continue
					}
					fmt.Println("evidence found, verified, and all content checks passed for", edge.Node.PredicateType)
				} else {
					fmt.Println("evidence found and verified for", edge.Node.PredicateType)
				}
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
	defer response.Body.Close()

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
	debug := os.Getenv("DEBUG") == "true"
	if debug {
		fmt.Println("in providerHandler")
	}

	svc := NewService(httpClient, "", debug)
	svc.ContentChecks = contentChecks
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
			fmt.Println("processing image:", key)
		}
		// parse the image reference
		registry, repository, image, tagOrDigest, err := svc.SplitImageKey(key)
		if err != nil {
			svc.sendResponse(nil, fmt.Sprintf("unable to split image key for %s: %v", key, err), w)
			return
		}

		var digest string
		var tag string

		// Check if already referenced by digest (starts with "sha256:")
		if strings.HasPrefix(tagOrDigest, "sha256:") {
			digest = strings.TrimPrefix(tagOrDigest, "sha256:")
			tag = tagOrDigest // Use full digest as tag for evidence path
		} else {
			// Tag reference - need to resolve digest via API
			tag = tagOrDigest
			digest, err = svc.getJFrogImageInfo(registry, repository, image, tag)
			if err != nil {
				svc.sendResponse(nil, fmt.Sprintf("unable to get digest for %s: %v", key, err), w)
				return
			}
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
		log.Printf("error encoding response to client: %v", err)
	}
}

// SplitImageKey parses an image reference into its components.
// Supports both tag format (registry/repo/image:tag) and digest format (registry/repo/image@sha256:...).
func (s *Service) SplitImageKey(key string) (string, string, string, string, error) {
	var tagOrDigest string
	var imageAddress string

	// Check if this is a digest reference (contains @sha256:)
	if idx := strings.Index(key, "@sha256:"); idx != -1 {
		imageAddress = key[:idx]
		tagOrDigest = key[idx+1:] // includes "sha256:..."
	} else {
		// Tag reference - split on last colon (to handle port numbers in registry)
		lastColon := strings.LastIndex(key, ":")
		if lastColon == -1 {
			return "", "", "", "", fmt.Errorf("key %q missing tag separator ':' or digest '@'", key)
		}
		imageAddress = key[:lastColon]
		tagOrDigest = key[lastColon+1:]
	}

	parts := strings.Split(imageAddress, "/")
	if len(parts) < 3 {
		return "", "", "", "", fmt.Errorf("key %q missing registry/repository/image parts", key)
	}

	registry := parts[0]
	repository := parts[1]
	image := strings.Join(parts[2:], "/")

	if s.Debug {
		fmt.Println("registry:", registry, "repository:", repository, "image:", image, "tagOrDigest:", tagOrDigest)
	}

	return registry, repository, image, tagOrDigest, nil
}

// loadContentChecksFromConfigMap reads the jfrog-provider-content-checks
// ConfigMap via the in-cluster Kubernetes API. Each data value in the ConfigMap
// is expected to be a JSON object mapping predicate types to an array of
// JMESPath expressions. If the ConfigMap does not exist or the API is
// unreachable the provider starts with no content checks (feature is optional).
//
// Example ConfigMap data value:
//
//	{
//	  "https://in-toto.io/attestation/vuln/v0.1": [
//	    "predicate.scanner.result == `PASSED`",
//	    "predicate.scanner.name == `Xray`"
//	  ]
//	}
func loadContentChecksFromConfigMap() map[string][]string {
	fmt.Println("loading content checks from config map")
	checks := make(map[string][]string)

	token, err := os.ReadFile(k8sTokenPath)
	if err != nil {
		fmt.Printf("skipping content checks: unable to read service account token: %v\n", err)
		return checks
	}

	namespace, err := os.ReadFile(k8sNamespacePath)
	if err != nil {
		fmt.Printf("skipping content checks: unable to read namespace: %v\n", err)
		return checks
	}

	caCert, err := os.ReadFile(k8sCACertPath)
	if err != nil {
		fmt.Printf("skipping content checks: unable to read CA cert: %v\n", err)
		return checks
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		fmt.Println("skipping content checks: unable to parse Kubernetes CA certificate")
		return checks
	}

	k8sClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    caCertPool,
				MinVersion: tls.VersionTLS12,
			},
		},
	}

	url := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/configmaps/%s",
		strings.TrimSpace(string(namespace)), contentChecksConfigMap)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Printf("skipping content checks: %v\n", err)
		return checks
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))

	resp, err := k8sClient.Do(req)
	if err != nil {
		fmt.Printf("skipping content checks: unable to reach Kubernetes API: %v\n", err)
		return checks
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		fmt.Printf("content checks configmap %q not found (skipping)\n", contentChecksConfigMap)
		return checks
	}
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("skipping content checks: Kubernetes API returned %s\n", resp.Status)
		return checks
	}

	var cm k8sConfigMap
	if err := json.NewDecoder(resp.Body).Decode(&cm); err != nil {
		fmt.Printf("skipping content checks: unable to decode configmap: %v\n", err)
		return checks
	}

	fmt.Println("cm.Data:", cm.Data)

	for dataKey, dataValue := range cm.Data {
		var entryChecks map[string][]string
		if err := json.Unmarshal([]byte(dataValue), &entryChecks); err != nil {
			fmt.Printf("skipping content check entry %q: %v\n", dataKey, err)
			continue
		}
		for predicateType, exprs := range entryChecks {
			fmt.Printf("predicateType: %s, expressions: %v\n", predicateType, exprs)
			checks[predicateType] = append(checks[predicateType], exprs...)
		}
	}

	fmt.Printf("loaded %d content check rule(s) from configmap %s\n", len(checks), contentChecksConfigMap)
	return checks
}

// validateEdidenceContent evaluates a JMESPath expression against the full
// evidence node. The check passes when the expression returns a truthy value
// (non-nil, non-false, non-empty string/slice/map). Returns nil on success.
func (s *Service) validateEdidenceContent(evidence EvidenceNode, expression string) error {
	raw, err := json.Marshal(evidence)
	if err != nil {
		return fmt.Errorf("failed to marshal evidence node: %v", err)
	}
	var evidenceData interface{}
	if err := json.Unmarshal(raw, &evidenceData); err != nil {
		return fmt.Errorf("failed to parse evidence JSON: %v", err)
	}

	result, err := jmespath.Search(expression, evidenceData)
	if err != nil {
		return fmt.Errorf("JMESPath expression %q failed: %v", expression, err)
	}

	if s.Debug {
		fmt.Printf("JMESPath expression %q returned: %v\n", expression, result)
	}

	if !isTruthy(result) {
		return fmt.Errorf("JMESPath expression %q evaluated to falsy value: %v", expression, result)
	}
	return nil
}

// isTruthy applies JMESPath truthiness rules: nil, false, empty string, empty
// slice, and empty map are falsy; everything else is truthy.
func isTruthy(v interface{}) bool {
	if v == nil {
		return false
	}
	switch val := v.(type) {
	case bool:
		return val
	case string:
		return val != ""
	case []interface{}:
		return len(val) > 0
	case map[string]interface{}:
		return len(val) > 0
	default:
		return true
	}
}

func NewService(client *http.Client, token string, debug bool) *Service {
	return &Service{
		Client: client,
		Token:  token,
		Debug:  debug,
	}
}
