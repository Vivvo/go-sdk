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
	GetService(service string) string
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

func (c *ConsulService) GetService(service string) string {
	tag := os.Getenv("TAG")
	name := os.Getenv("CONSUL_SERVICE_NAME")
	if name == "" {
		name = "service.consul"
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
		randomService := services[c.rng.Intn(len(services))].Service
		newHost = fmt.Sprintf("%s:%d", randomService.Address, randomService.Port)
	} else {
		_, addrs, err := net.LookupSRV(service, tag, name)
		if err != nil || len(addrs) == 0 {
			return service
		}
		newHost = fmt.Sprintf("%s:%d", addrs[0].Target, addrs[0].Port)
	}

	log.Println("Remapping host", "service", service, "serviceMapping", newHost)

	return newHost
}
