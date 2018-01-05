package main

import (
	"io/ioutil"
	"log"
	"strings"

	"cloud.google.com/go/compute/metadata"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/servicemanagement/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Config is the configuration structure used by the LambdaController
type Config struct {
	Project               string
	ProjectNum            string
	OAuthClientID         string
	OAuthClientSecret     string
	clientCompute         *compute.Service
	clientResourceManager *cloudresourcemanager.Service
	clientServiceMan      *servicemanagement.APIService
	clientset             *kubernetes.Clientset
}

func (c *Config) loadAndValidate() error {
	var err error

	clusterConfig, err := rest.InClusterConfig()
	if err != nil {
		return err
	}

	clientset, err := kubernetes.NewForConfig(clusterConfig)
	if err != nil {
		return err
	}
	c.clientset = clientset

	clientScopes := []string{
		compute.ComputeScope,
		servicemanagement.ServiceManagementScope,
		cloudresourcemanager.CloudPlatformScope,
	}

	client, err := google.DefaultClient(oauth2.NoContext, strings.Join(clientScopes, " "))
	if err != nil {
		return err
	}

	log.Printf("[INFO] Instantiating GCE client...")
	c.clientCompute, err = compute.New(client)

	log.Printf("[INFO] Instantiating Google Cloud ResourceManager Client...")
	c.clientResourceManager, err = cloudresourcemanager.New(client)
	if err != nil {
		return err
	}

	log.Printf("[INFO] Instantiating Google Cloud Service Management Client...")
	c.clientServiceMan, err = servicemanagement.New(client)
	if err != nil {
		return err
	}

	if c.Project == "" {
		log.Printf("[INFO] Fetching Project ID from Compute metadata API...")
		c.Project, err = metadata.ProjectID()
		if err != nil {
			return err
		}
	}

	if c.ProjectNum == "" {
		log.Printf("[INFO] Fetching Numeric Project ID from Compute metadata API...")
		c.ProjectNum, err = metadata.NumericProjectID()
		if err != nil {
			return err
		}
	}

	// Load OAuth client id and secret
	clientID, err := ioutil.ReadFile(clientIDPath)
	if err != nil {
		log.Printf("[ERROR] Failed to read clientID from: %s", clientIDPath)
		return err
	}
	c.OAuthClientID = string(clientID)

	clientSecret, err := ioutil.ReadFile(clientSecretPath)
	if err != nil {
		log.Printf("[ERROR] Failed to read clientSecret from: %s", clientSecretPath)
		return err
	}
	c.OAuthClientSecret = string(clientSecret)

	return nil
}
