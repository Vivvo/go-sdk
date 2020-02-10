package trustprovider

import (
	"encoding/json"
	"fmt"
	"github.com/go-redis/redis"
	"log"
)

// RedisAccount is a slightly more persistent implementation of the Account interface that the TrustProvider will
// use to save tokens associated with accounts and retrieve accounts by those tokens. This implementation
// is NOT suitable for production use.
type RedisAccount struct {
	redisClient     *redis.Client
	namespacePrefix string // all keys will be prefixed with this
}

func NewRedisAccount(connectionString string, namespacePrefix string) (*RedisAccount, error) {
	redisOpts, err := redis.ParseURL(connectionString)
	if err != nil {
		return nil, fmt.Errorf("error parsing connection string: %w", err)
	}

	redisClient := redis.NewClient(redisOpts)
	_, err = redisClient.Ping().Result()
	if err != nil {
		return nil, fmt.Errorf("failed to ping redis: %w", err)
	}

	return &RedisAccount{redisClient: redisClient, namespacePrefix: namespacePrefix}, nil
}

func (r *RedisAccount) Update(account interface{}, token string) error {

	b, err := json.Marshal(account)
	if err != nil {
		log.Printf("Error marshalling account: %s", err)
		return err
	}

	err = r.redisClient.Set(fmt.Sprintf("%s:%s", r.namespacePrefix, token), b, 0).Err()
	if err != nil {
		log.Printf("Error setting account: %s", err)
		return err
	}

	return err
}

func (r *RedisAccount) Read(token string) (interface{}, error) {

	val, err := r.redisClient.Get(fmt.Sprintf("%s:%s", r.namespacePrefix, token)).Result()
	if err != nil {
		return nil, fmt.Errorf("error reading account: %w", err)
	}

	var account interface{}
	err = json.Unmarshal([]byte(val), &account)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling result: %w", err)
	}

	return account, nil
}
