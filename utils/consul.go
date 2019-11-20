package utils

import (
	"fmt"
	"github.com/hashicorp/consul/api"
	"log"
	"math/rand"
	"net"
	"os"
	"time"
)

type ConsulServiceInterface interface {
	GetService(service string, _tag ...string) string
}

type ConsulHealth interface {
	Service(service, tag string, passingOnly bool, q *api.QueryOptions) ([]*api.ServiceEntry, *api.QueryMeta, error)
}

type ConsulService struct {
	health ConsulHealth
	rng    *rand.Rand
}

func NewConsulService(address string) (ConsulServiceInterface, error) {
	service := ConsulService{}
	client, err := api.NewClient(&api.Config{Address: address})
	if err == nil {
		service.health = client.Health()

		s := rand.NewSource(time.Now().Unix())
		service.rng = rand.New(s)
	}

	return &service, err
}

func (c *ConsulService) filterByUntagged(services []*api.ServiceEntry) []*api.ServiceEntry {
	var filteredServices []*api.ServiceEntry
	for _, service := range services {
		if len(service.Service.Tags) == 0 {
			filteredServices = append(filteredServices, service)
		}
	}
	return filteredServices
}

func (c *ConsulService) GetService(service string, _tag ...string) string {
	var tag string
	if len(_tag) > 0 && _tag[0] != "" {
		tag = _tag[0]
	} else {
		tag = os.Getenv("TAG")
		if tag == "" {
			tag = os.Getenv("TENANT_NAME")
		}
	}

	var newHost string
	if tag == "" {
		services, _, err := c.health.Service(service, tag, true, nil)
		if err != nil {
			log.Println("Error looking up service in consul", "errorMsg", err.Error(), "service", service)
			return service
		}

		if len(services) == 0 {
			log.Println("No matching services found in consul", "service", service)
			return service
		}

		filteredServices := c.filterByUntagged(services)
		if len(filteredServices) == 0 {
			log.Println("Tag was left empty but all matching services in consul are tagged. Defaulting to using a random tagged service.", "service", service)
		} else {
			services = filteredServices
		}

		randomService := services[c.rng.Intn(len(services))].Service
		newHost = fmt.Sprintf("%s:%d", randomService.Address, randomService.Port)
	} else {
		// K8s Lookup
		_, addrs, err := net.LookupSRV("", "", fmt.Sprintf("_https._tcp.%s.%s.svc.cluster.local", service, tag))
		if err != nil || len(addrs) == 0 {
			log.Println("No matching srv record found. Falling back to Consul lookup", "service", service)

			// Consul Lookup
			_, addrs, err = net.LookupSRV(service, tag, "service.consul")
			if err != nil || len(addrs) == 0 {
				log.Println("No matching srv record found.", "service", service)
				return service
			}
		}

		newHost = fmt.Sprintf("%s:%d", addrs[0].Target, addrs[0].Port)
	}

	log.Println("Remapping host", "service", service, "serviceMapping", newHost)

	return newHost
}
