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
	var newHost string
	if tag == "" {
		_, addrs, err := net.LookupSRV("", "", service)
		if err != nil || len(addrs) == 0 {
			return service
		}
		newHost = fmt.Sprintf("%s:%d", addrs[0].Target, addrs[0].Port)
	} else {
		_, addrs, err := net.LookupSRV(service, tag, "service.consul")
		if err != nil || len(addrs) == 0 {
			return service
		}
		newHost = fmt.Sprintf("%s:%d", addrs[0].Target, addrs[0].Port)
	}

	log.Println("Remapping host", "service", service, "serviceMapping", newHost)

	return newHost
}
