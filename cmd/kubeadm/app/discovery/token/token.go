/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package token

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"sync"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/kubernetes/cmd/kubeadm/app/constants"
	kubeconfigutil "k8s.io/kubernetes/cmd/kubeadm/app/util/kubeconfig"
	"k8s.io/kubernetes/cmd/kubeadm/app/util/pubkeypin"
	tokenutil "k8s.io/kubernetes/cmd/kubeadm/app/util/token"
	bootstrapapi "k8s.io/kubernetes/pkg/bootstrap/api"
	"k8s.io/kubernetes/pkg/controller/bootstrap"
)

const BootstrapUser = "token-bootstrap-client"

// ClusterInfoMaxSizeBytes is the maximum allowed size of the cluster-info ConfigMap (in bytes)
const ClusterInfoMaxSizeBytes = 1024 * 1024 * 10 // 10 MiB

var (
	errInsecureClientUsedMoreThanOnce = fmt.Errorf("client must be used for only a single request")
	errInsecureClientEmptyCertChain   = fmt.Errorf("expected at least one server certificate")
	errInsecureClientNoRequest        = fmt.Errorf("doRequest did not make a request using the withInsecureHTTPClient client")
	errInvalidPEMData                 = fmt.Errorf("invalid PEM data")
	errTrailingPEMData                = fmt.Errorf("trailing data after first PEM block")
)

// RetrieveValidatedClusterInfo connects to the API Server and tries to fetch the cluster-info ConfigMap
// It then makes sure it can trust the API Server by looking at the JWS-signed tokens
func RetrieveValidatedClusterInfo(discoveryToken string, tokenAPIServers, rootCAPubKeys []string) (*clientcmdapi.Cluster, error) {
	tokenId, tokenSecret, err := tokenutil.ParseToken(discoveryToken)
	if err != nil {
		return nil, err
	}

	// Load the cfg.TLSDiscoveryRootCAPubKeys into a pubkeypin.Set
	pubKeyPins := pubkeypin.NewSet()
	err = pubKeyPins.Allow(rootCAPubKeys...)
	if err != nil {
		return nil, err
	}

	// The function below runs for every endpoint, and all endpoints races with each other.
	// The endpoint that wins the race and completes the task first gets its kubeconfig returned below
	baseKubeConfig := runForEndpointsAndReturnFirst(tokenAPIServers, func(endpoint string) (*clientcmdapi.Config, error) {

		// clusterInfoURL is the URL of the bootstrap cluster info ConfigMap on the Kubernetes API
		clusterInfoURLString := fmt.Sprintf(
			"https://%s/api/v1/namespaces/%s/configmaps/%s",
			endpoint,
			metav1.NamespacePublic,
			bootstrapapi.ConfigMapClusterInfo)
		clusterInfoURL, err := url.Parse(clusterInfoURLString)
		if err != nil {
			return nil, fmt.Errorf("invalid URL %q, can't connect: %v", clusterInfoURLString, err)
		}
		fmt.Printf("[discovery] Requesting cluster-info from %q\n", clusterInfoURL)

		var clusterinfo *v1.ConfigMap
		var bootstrapCertificateChain []*x509.Certificate

		wait.PollImmediateInfinite(constants.DiscoveryRetryInterval, func() (bool, error) {
			response, certificates, err := withInsecureHTTPClient(func(client *http.Client) (*http.Response, error) {
				return client.Get(clusterInfoURL.String())
			})
			if err != nil {
				fmt.Printf("[discovery] Failed to request cluster info, will try again: [%s]\n", err)
				return false, nil
			}
			defer response.Body.Close()

			// Read the entire response body (up to ClusterInfoMaxSizeBytes)
			responseBytes, err := ioutil.ReadAll(http.MaxBytesReader(nil, response.Body, ClusterInfoMaxSizeBytes))
			fmt.Printf("[discovery] Actual cluster info was %d bytes\n", len(responseBytes))
			if err != nil {
				fmt.Printf("[discovery] Failed to read cluster info response, will try again: [%s]\n", err)
				return false, nil
			}

			// Parse the JSON into a ConfigMap
			err = json.Unmarshal(responseBytes, &clusterinfo)
			if err != nil {
				fmt.Printf("[discovery] Failed to parse cluster info response, will try again: [%s]\n", err)
				return false, nil
			}

			// Success, so save off the certificate chain for later validation
			bootstrapCertificateChain = certificates
			return true, nil
		})

		kubeConfigString, ok := clusterinfo.Data[bootstrapapi.KubeConfigKey]
		if !ok || len(kubeConfigString) == 0 {
			return nil, fmt.Errorf("there is no %s key in the %s ConfigMap. This API Server isn't set up for token bootstrapping, can't connect", bootstrapapi.KubeConfigKey, bootstrapapi.ConfigMapClusterInfo)
		}
		detachedJWSToken, ok := clusterinfo.Data[bootstrapapi.JWSSignatureKeyPrefix+tokenId]
		if !ok || len(detachedJWSToken) == 0 {
			return nil, fmt.Errorf("there is no JWS signed token in the %s ConfigMap. This token id %q is invalid for this cluster, can't connect", bootstrapapi.ConfigMapClusterInfo, tokenId)
		}
		if !bootstrap.DetachedTokenIsValid(detachedJWSToken, kubeConfigString, tokenId, tokenSecret) {
			return nil, fmt.Errorf("failed to verify JWS signature of received cluster info object, can't trust this API Server")
		}

		finalConfig, err := clientcmd.Load([]byte(kubeConfigString))
		if err != nil {
			return nil, fmt.Errorf("couldn't parse the kubeconfig file in the %s configmap: %v", bootstrapapi.ConfigMapClusterInfo, err)
		}

		// If no TLS root CA pinning was specified, we're done.
		if pubKeyPins.Empty() {
			fmt.Printf("[discovery] Cluster info signature and contents are valid and no TLS pinning was specified, will use API Server %q\n", endpoint)
			return finalConfig, nil
		}

		// For each cluster, validate that its CA matches a pinned key and save that root into an x509.CertPool
		pinnedRoots := x509.NewCertPool()
		for _, cluster := range finalConfig.Clusters {
			caCert, err := getClusterCA(cluster)
			if err != nil {
				return nil, fmt.Errorf("could not get cluster CA from %s configmap: %v", bootstrapapi.ConfigMapClusterInfo, err)
			}

			err = pubKeyPins.Check(caCert)
			if err != nil {
				return nil, fmt.Errorf("unknown cluster CA: %v", err)
			}

			pinnedRoots.AddCert(caCert)
		}

		// Build an intermediate CA pool containing all the non-leaf certificates sent by the server
		chainCerts := x509.NewCertPool()
		for _, chainCert := range bootstrapCertificateChain[1:] {
			chainCerts.AddCert(chainCert)
		}

		// Now that we know the root CA pool, validate the original certificate chain
		// against the server's hostname
		_, err = bootstrapCertificateChain[0].Verify(x509.VerifyOptions{
			DNSName:       clusterInfoURL.Hostname(),
			Roots:         pinnedRoots,
			Intermediates: chainCerts,
		})
		if err != nil {
			return nil, fmt.Errorf("server certificate is not valid for expected hostname %q", clusterInfoURL.Hostname())
		}

		fmt.Printf("[discovery] Cluster info signature and contents are valid and TLS certificate validates against pinned roots, will use API Server %q\n", endpoint)
		return finalConfig, nil
	})

	return kubeconfigutil.GetClusterFromKubeConfig(baseKubeConfig), nil
}

// runForEndpointsAndReturnFirst loops the endpoints slice and let's the endpoints race for connecting to the master
func runForEndpointsAndReturnFirst(endpoints []string, fetchKubeConfigFunc func(string) (*clientcmdapi.Config, error)) *clientcmdapi.Config {
	stopChan := make(chan struct{})
	var resultingKubeConfig *clientcmdapi.Config
	var once sync.Once
	var wg sync.WaitGroup
	for _, endpoint := range endpoints {
		wg.Add(1)
		go func(apiEndpoint string) {
			defer wg.Done()
			wait.Until(func() {
				fmt.Printf("[discovery] Trying to connect to API Server %q\n", apiEndpoint)
				cfg, err := fetchKubeConfigFunc(apiEndpoint)
				if err != nil {
					fmt.Printf("[discovery] Failed to connect to API Server %q: %v\n", apiEndpoint, err)
					return
				}
				fmt.Printf("[discovery] Successfully established connection with API Server %q\n", apiEndpoint)

				// connection established, stop all wait threads
				once.Do(func() {
					close(stopChan)
					resultingKubeConfig = cfg
				})
			}, constants.DiscoveryRetryInterval, stopChan)
		}(endpoint)
	}
	wg.Wait()
	return resultingKubeConfig
}

// certChain is an array of *x509.Certificate with a helper to plug into the tls VerifyPeerCertificate hook
type certChain []*x509.Certificate

// saveCertificateChain parses and saves the array of DER-encoded certificates into a certChain
func (c *certChain) saveCertificateChain(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	// Make sure this wrapper is being used correctly
	if len(*c) != 0 {
		return errInsecureClientUsedMoreThanOnce
	}

	// Do a quick sanity check (this should never happen)
	if len(rawCerts) < 1 {
		return errInsecureClientEmptyCertChain
	}

	// Parse and collect each certificate
	for _, rawCert := range rawCerts {
		cert, err := x509.ParseCertificate(rawCert)
		if err != nil {
			return err
		}
		*c = append(*c, cert)
	}

	return nil
}

// withInsecureHTTPClient creates a temporary http.Client, passes it to doRequest(...),
// which should perform a single HTTP request and return the response. The temporary
// client will not validate TLS certificates in real time, but instead will capture
// and return the certificates for post-hoc validation.
func withInsecureHTTPClient(
	doRequest func(*http.Client) (*http.Response, error),
) (*http.Response, []*x509.Certificate, error) {

	// certificates will collect the certificate chain presented by the server
	var certificates certChain

	// Create an HTTP client with a custom TLS transport that saves off the certificate chain for later validation
	insecureClient := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify:    true,
				VerifyPeerCertificate: certificates.saveCertificateChain,
			},
		},
	}

	// Perform what should be a single request using the client
	response, err := doRequest(&insecureClient)
	if err != nil {
		return nil, nil, err
	}

	// Make sure the wrapper is being used correctly
	if len(certificates) == 0 {
		response.Body.Close()
		return nil, nil, errInsecureClientNoRequest
	}
	return response, certificates, nil
}

// getClusterCA extracts and decodes the root CA section from a clientcmdapi.Cluster
func getClusterCA(cluster *clientcmdapi.Cluster) (*x509.Certificate, error) {
	pemBlock, trailingData := pem.Decode(cluster.CertificateAuthorityData)
	if pemBlock == nil {
		return nil, errInvalidPEMData
	}
	if len(trailingData) != 0 {
		return nil, errTrailingPEMData
	}
	return x509.ParseCertificate(pemBlock.Bytes)
}
