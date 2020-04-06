# Change Log

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

<a name="1.21.0"></a>
# [1.21.0](https://github.com/Vivvo/go-sdk/compare/v1.20.0...v1.21.0) (2020-04-06)


### Features

* **[RDNG-753]:** added new Business Director Credential ([4de3951](https://github.com/Vivvo/go-sdk/commit/4de3951))



<a name="1.20.0"></a>
# [1.20.0](https://github.com/Vivvo/go-sdk/compare/v1.19.2...v1.20.0) (2020-04-06)


### Features

* **trustprovider:** default_account_manager add mux lock around file ops ([9184456](https://github.com/Vivvo/go-sdk/commit/9184456))



<a name="1.19.2"></a>
## [1.19.2](https://github.com/Vivvo/go-sdk/compare/v1.19.1...v1.19.2) (2020-03-11)


### Bug Fixes

* **rdng-601:** handle OAuth2.0 scopes properly ([5b9f698](https://github.com/Vivvo/go-sdk/commit/5b9f698))



<a name="1.19.1"></a>
## [1.19.1](https://github.com/Vivvo/go-sdk/compare/v1.19.0...v1.19.1) (2020-03-11)


### Bug Fixes

* **rdng-601:** look for scp not scopes in the access token ([3a0f5b8](https://github.com/Vivvo/go-sdk/commit/3a0f5b8))



<a name="1.19.0"></a>
# [1.19.0](https://github.com/Vivvo/go-sdk/compare/v1.18.0...v1.19.0) (2020-03-10)


### Features

* **rdng-601:** oAuth 2.0 authorization method for trust providers ([9def261](https://github.com/Vivvo/go-sdk/commit/9def261))



<a name="1.17.0"></a>
# [1.17.0](https://github.com/Vivvo/go-sdk/compare/v1.16.3...v1.17.0) (2020-03-06)


### Features

* **[RDNG-593]:** add userOverrideConsent to DataBundlesDto ([00c9dd8](https://github.com/Vivvo/go-sdk/commit/00c9dd8))



<a name="1.16.3"></a>
## [1.16.3](https://github.com/Vivvo/go-sdk/compare/v1.16.2...v1.16.3) (2020-03-02)


### Bug Fixes

* **config:** move two env configs to const names ([85c4403](https://github.com/Vivvo/go-sdk/commit/85c4403))



<a name="1.16.0"></a>
# [1.16.0](https://github.com/Vivvo/go-sdk/compare/v1.15.4...v1.16.0) (2020-02-13)


### Features

* **redisAccountManager:** add ReadInto function ([5138362](https://github.com/Vivvo/go-sdk/commit/5138362))



<a name="1.15.4"></a>
## [1.15.4](https://github.com/Vivvo/go-sdk/compare/v1.15.3...v1.15.4) (2020-02-12)



<a name="1.15.3"></a>
## [1.15.3](https://github.com/Vivvo/go-sdk/compare/v1.15.2...v1.15.3) (2020-02-10)


### Bug Fixes

* **redisAccountManager:** add json marshalling and unmarshalling to redisAccountManager ([4909488](https://github.com/Vivvo/go-sdk/commit/4909488))



<a name="1.15.2"></a>
## [1.15.2](https://github.com/Vivvo/go-sdk/compare/v1.15.1...v1.15.2) (2020-02-10)


### Bug Fixes

* **imports:** dont use relative imports! ([1b2882c](https://github.com/Vivvo/go-sdk/commit/1b2882c))



<a name="1.15.1"></a>
## [1.15.1](https://github.com/Vivvo/go-sdk/compare/v1.15.0...v1.15.1) (2020-02-10)



<a name="1.15.0"></a>
# [1.15.0](https://github.com/Vivvo/go-sdk/compare/v1.14.8...v1.15.0) (2020-02-10)


### Features

* **redisAccount:** add a redis account manager for more persistent mock adapterrs ([f643610](https://github.com/Vivvo/go-sdk/commit/f643610))



<a name="1.14.8"></a>
## [1.14.8](https://github.com/Vivvo/go-sdk/compare/v1.14.7...v1.14.8) (2020-02-06)



<a name="1.14.6"></a>
## [1.14.6](https://github.com/Vivvo/go-sdk/compare/v1.14.5...v1.14.6) (2020-02-06)



<a name="1.14.5"></a>
## [1.14.5](https://github.com/Vivvo/go-sdk/compare/v1.14.4...v1.14.5) (2020-02-06)



<a name="1.14.2"></a>
## [1.14.2](https://github.com/Vivvo/go-sdk/compare/v1.14.1...v1.14.2) (2020-02-05)


### Bug Fixes

* **[RDNG-515]:** made DecryptPayload method smarter, decodes the b64 payload and keys ([af4d072](https://github.com/Vivvo/go-sdk/commit/af4d072))



<a name="1.12.1"></a>
## [1.12.1](https://github.com/Vivvo/go-sdk/compare/v1.12.0...v1.12.1) (2020-02-05)


### Bug Fixes

* **[RDNG-515]:** unmarshal into passed in interface ([233d470](https://github.com/Vivvo/go-sdk/commit/233d470))



<a name="1.12.0"></a>
# [1.12.0](https://github.com/Vivvo/go-sdk/compare/v1.11.4...v1.12.0) (2020-02-05)


### Features

* **[RDNG-515]:** AES-256 encrypt payload, then rsa encode the nonce and key to the payload with the ([d42a6c9](https://github.com/Vivvo/go-sdk/commit/d42a6c9))



<a name="1.11.4"></a>
## [1.11.4](https://github.com/Vivvo/go-sdk/compare/v1.11.3...v1.11.4) (2020-02-05)



<a name="1.11.3"></a>
## [1.11.3](https://github.com/Vivvo/go-sdk/compare/v1.11.2...v1.11.3) (2020-02-04)


### Bug Fixes

* **[RDNG-515]:** added missing "New" method to DataBundleService ([7c2dd19](https://github.com/Vivvo/go-sdk/commit/7c2dd19))



<a name="1.11.2"></a>
## [1.11.2](https://github.com/Vivvo/go-sdk/compare/v1.11.1...v1.11.2) (2020-02-04)


### Bug Fixes

* **[RDNG-515]:** added missing DataBundleServiceInterface ([a585a83](https://github.com/Vivvo/go-sdk/commit/a585a83))



<a name="1.11.1"></a>
## [1.11.1](https://github.com/Vivvo/go-sdk/compare/v1.11.0...v1.11.1) (2020-02-04)


### Bug Fixes

* **consul:** use kuberenetes dns to find consul in NewConsulTLSService ([45ad0a6](https://github.com/Vivvo/go-sdk/commit/45ad0a6))



<a name="1.11.0"></a>
# [1.11.0](https://github.com/Vivvo/go-sdk/compare/v1.10.3...v1.11.0) (2020-02-03)


### Features

* **[RDNG-504]:** look for PublishWrapperDto when recieving a databundle ([8c80783](https://github.com/Vivvo/go-sdk/commit/8c80783))



<a name="1.10.2"></a>
## [1.10.2](https://github.com/Vivvo/go-sdk/compare/v1.10.1...v1.10.2) (2020-02-03)



<a name="1.10.1"></a>
## [1.10.1](https://github.com/Vivvo/go-sdk/compare/v1.10.0...v1.10.1) (2020-02-03)



<a name="1.10.0"></a>
# [1.10.0](https://github.com/Vivvo/go-sdk/compare/v1.9.2...v1.10.0) (2020-01-30)


### Features

* **[RDNG-488]:** added functions for publishing encrypted data bundles and decrypting them ([4ff5968](https://github.com/Vivvo/go-sdk/commit/4ff5968))



<a name="1.9.1"></a>
## [1.9.1](https://github.com/Vivvo/go-sdk/compare/v1.9.0...v1.9.1) (2020-01-14)



<a name="1.9.0"></a>
# [1.9.0](https://github.com/Vivvo/go-sdk/compare/v1.8.1...v1.9.0) (2019-12-27)


### Features

* **tls:** build tls signRequest automatically if possible ([42b5551](https://github.com/Vivvo/go-sdk/commit/42b5551))



<a name="1.8.1"></a>
## [1.8.1](https://github.com/Vivvo/go-sdk/compare/v1.8.0...v1.8.1) (2019-12-27)


### Bug Fixes

* **config:** buildsignrequest add https ([a1026ae](https://github.com/Vivvo/go-sdk/commit/a1026ae))



<a name="1.8.0"></a>
# [1.8.0](https://github.com/Vivvo/go-sdk/compare/v1.7.0...v1.8.0) (2019-12-27)


### Features

* **configless:** add functions to build tls SignRequest and Consul TLS automagically ([ac24cbe](https://github.com/Vivvo/go-sdk/commit/ac24cbe))



<a name="1.5.1"></a>
## [1.5.1](https://github.com/Vivvo/go-sdk/compare/v1.5.0...v1.5.1) (2019-11-21)


### Bug Fixes

* **tls:** derive resty certPool from system cert pool ([1b8e3bd](https://github.com/Vivvo/go-sdk/commit/1b8e3bd))



<a name="1.5.0"></a>
# [1.5.0](https://github.com/Vivvo/go-sdk/compare/v1.4.3...v1.5.0) (2019-11-20)


### Features

* **RDNG-267:** add k8 srv lookup, fall back to consul ([310d1c6](https://github.com/Vivvo/go-sdk/commit/310d1c6))



<a name="1.4.3"></a>
## [1.4.3](https://github.com/Vivvo/go-sdk/compare/v1.4.2...v1.4.3) (2019-11-20)



<a name="1.4.2"></a>
## [1.4.2](https://github.com/Vivvo/go-sdk/compare/v1.4.1...v1.4.2) (2019-11-19)


### Bug Fixes

* **trustProvider:** fix tlsPort config ([b4cd362](https://github.com/Vivvo/go-sdk/commit/b4cd362))



<a name="1.4.1"></a>
## [1.4.1](https://github.com/Vivvo/go-sdk/compare/v1.4.0...v1.4.1) (2019-11-19)


### Bug Fixes

* **tls:** add configurable tls port and listenAndServe uses tp router now ([a306221](https://github.com/Vivvo/go-sdk/commit/a306221))



<a name="1.3.0"></a>
# [1.3.0](https://github.com/Vivvo/go-sdk/compare/v1.2.1...v1.3.0) (2019-10-28)


### Bug Fixes

* Update to work with the more generate public keys ([4cc9a79](https://github.com/Vivvo/go-sdk/commit/4cc9a79))
* Use the x/crypto package for now ([ac9f5e2](https://github.com/Vivvo/go-sdk/commit/ac9f5e2))


### Features

* **DIDAuth:** Support DIDAuth with Ed25519 keys ([5f815db](https://github.com/Vivvo/go-sdk/commit/5f815db))



<a name="1.2.1"></a>
## [1.2.1](https://github.com/Vivvo/go-sdk/compare/v1.2.0...v1.2.1) (2019-10-25)


### Bug Fixes

* **RDNG-129:** merge decrypted body and keep "encrypted" body when onboarding because the encrypted ([d235c60](https://github.com/Vivvo/go-sdk/commit/d235c60))



<a name="1.2.0"></a>
# [1.2.0](https://github.com/Vivvo/go-sdk/compare/v1.1.1...v1.2.0) (2019-10-18)


### Features

* **TrustProviders:** Remove callbacks from the trust provider sdk ([fd20613](https://github.com/Vivvo/go-sdk/commit/fd20613))
