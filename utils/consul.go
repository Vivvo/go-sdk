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
	// single tenant quick lookup
	_, addrs, err := net.LookupSRV(service, "", "service.consul")
	if err == nil || len(addrs) == 1 {
		return fmt.Sprintf("%s:%d", addrs[0].Target, addrs[0].Port)
	}

	// multi-tenant lookup by tag
	services, _, err := c.health.Service(service, os.Getenv("TAG"), true, nil)
	if err != nil || len(services) == 0 {
		return service
	}
	randomService := services[c.rng.Intn(len(services))].Service

	newHost := fmt.Sprintf("%s:%d", randomService.Address, randomService.Port)

	log.Printf("Remapping host %s -> %s", os.Getenv("TAG") + "-" + service, newHost)

	return newHost
}
