package trustprovider

import (
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

	err := r.redisClient.Set(fmt.Sprintf("%s:%s", r.namespacePrefix, token), account, 0).Err()
	if err != nil {
		log.Printf("Error creating file: %s", err)
		return err
	}

	return err
}

func (r *RedisAccount) Read(token string) (interface{}, error) {

	val, err := r.redisClient.Get(fmt.Sprintf("%s:%s", r.namespacePrefix, token)).Result()
	if err != nil {
		return nil, fmt.Errorf("error reading account: %w", err)
	}

	return val, nil
}
