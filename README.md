# AuthService (and Library)
Experimenting with RSA Keys, JWT Tokens, and OpenID Connect

-----------------------------

A very simple AuthN/AuthZ service that is compliant with the [OpenID Connect Authorization Standard](http://openid.net/developers/specs/).

* To be compliant with the OpenID Connect standard, an HTTP endpoint was set up to expose the OpenID Connect discovery struct at the address:```http://<ISSUER_URL>/.well-known/webfinder``` 
(see example response at the end of this document)
* It uses DynamoDB as a datastore for users, group membership, and private keys 
* The service issues JSON Web Tokens which contain standard claims (issuer, subject, audience...) as well as custom claims such as group membership information
* To get a token, a user presents his/her BasicAuth credentials to a login endpoint:

```
14:57 $ http --auth=adriano:password http://localhost/auth | jq -r .
{
  "token": "eyJhbGciOiJSUzUxMiIsInNpZ19raWQiOiJmYTg1NDRhYS0yYmQ1LTQxYmUtYTk1ZC1kZWE0NGQzNzM3MTgiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJhZHJpYW5vc2VsYS9hbGwiLCJleHAiOjE1MDg3MTMwNjEsImp0aSI6IjNmM2NhOTFmLTVhOWEtNDUwZi1iNDQxLTlmNjI5YWJiMmYxYiIsImlhdCI6MTUwODcwOTQ2MSwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwibmJmIjoxNTA4NzA5NDYxLCJzdWIiOiJiNDliNTZkNi00M2MwLTQ2ODUtYmM0OS0xMDYyYWE0YmI3YTkiLCJncnBzIjpbImM1Nzc2OTBiLWNiNzQtNDMyYi05ZDA1LWY3NzgwM2JmZTQyNSIsIjI3ZDQ4OWFiLTQxZTUtNDYzMi04NzJlLTdiYTRlYmFjZjIyOSIsImIwYmViNjhhLTEyMDQtNGZlNy1iYTkwLTBjODRiMjQxNDBmNCJdfQ.p3B4s3L2yQr-0knnA5lAfU3Lpf_sK2H0YHv4zTDXoNdUfwzDtkgdeuhv73j9_9AVfqHk2rlcmns3iDQ0duwvNYFKTY4oMpUqrDIXPVRqE4icVIeVHDGvA5AFzge6fnY5-TPXQBgQhK0Wy9LUVqBlhP72aAcki3GE-XR4uaaYQUfCSNP4MNdehMvIp2Mm9VF9VWInA1cwvxmaAqZCuCLySGERj6v_4ptkW63vrdlzoKtUC52e-Q5Zk_plEaMo4iwvbOlABO63jBi1KmJNjR3HKSFW8zqEuW7tWimEfFAAhrrmENVSKjhZ-8h03MoH4YxfGqkTWxYz36HeVz9SCxkaCA",
  "valid_until": 1508713061
}
```
* The tokens are signed with a Private Key and the signature can be validated by using the matching Public Key
* The Public Keys are made available as JWKs (JSON Web Keys) through the exposure endpoint:

```
$ http http://localhost/auth/keys | jq -r .
{
  "keys": [
    {
      "use": "sig",
      "kty": "RSA",
      "kid": "d58e57c1-200d-4192-9135-662c67f2ba4c",
      "alg": "RS512",
      "n": "2mOlLJK7Hq9Ua7HgVW8P3RgdK4dIlmIkkW3OBQtSAYtHn2-zgTW2_76NWGexwZeHRA2Qv03uV64ylxqg4l3FrDy5kKlfFx8mqwJG0tnG4NUHDkeOBn0cpC1jSFaXj_FggB2ZtQbuh35vY31LvcnMrkmTHle5VxQfqGakLUsYEnqHHwFcXrhWMxHpOSYjGLj9zqLMo5fEw42XK8BDME2OS8OloX7GYuAHVxGitkAem12-O2PKK6DpsV4ipGGubiM87xPl7wS5zE-cKxG4xJfHpYAC0ohNa-jFpNgN49Ywp7mOwgkMrfuiCysiR3pXZpmwSZFv1MMk11H1GnAo6-IfYQ",
      "e": "AQAB"
    },
    {
      "use": "sig",
      "kty": "RSA",
      "kid": "1504707f-9de4-4425-87a3-a047859fb97a",
      "alg": "RS512",
      "n": "2mOlLJK7Hq9Ua7HgVW8P3RgdK4dIlmIkkW3OBQtSAYtHn2-zgTW2_76NWGexwZeHRA2Qv03uV64ylxqg4l3FrDy5kKlfFx8mqwJG0tnG4NUHDkeOBn0cpC1jSFaXj_FggB2ZtQbuh35vY31LvcnMrkmTHle5VxQfqGakLUsYEnqHHwFcXrhWMxHpOSYjGLj9zqLMo5fEw42XK8BDME2OS8OloX7GYuAHVxGitkAem12-O2PKK6DpsV4ipGGubiM87xPl7wS5zE-cKxG4xJfHpYAC0ohNa-jFpNgN49Ywp7mOwgkMrfuiCysiR3pXZpmwSZFv1MMk11H1GnAo6-IfYQ",
      "e": "AQAB"
    }
  ]
}
```
* The Golang library in```/library/jwtvalidation``` pulls the keys for you by first looking at the token issuer's OpenID Discovery endpoint to find the address of the keys URL shown above
* Validation library CLI output:

```
14:57 $ jwt validate --jwt="eyJhbGciOiJSUzUxMiIsInNpZ19raWQiOiJmYTg1NDRhYS0yYmQ1LTQxYmUtYTk1ZC1kZWE0NGQzNzM3MTgiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJhZHJpYW5vc2VsYS9hbGwiLCJleHAiOjE1MDg3MTMwNjEsImp0aSI6IjNmM2NhOTFmLTVhOWEtNDUwZi1iNDQxLTlmNjI5YWJiMmYxYiIsImlhdCI6MTUwODcwOTQ2MSwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwibmJmIjoxNTA4NzA5NDYxLCJzdWIiOiJiNDliNTZkNi00M2MwLTQ2ODUtYmM0OS0xMDYyYWE0YmI3YTkiLCJncnBzIjpbImM1Nzc2OTBiLWNiNzQtNDMyYi05ZDA1LWY3NzgwM2JmZTQyNSIsIjI3ZDQ4OWFiLTQxZTUtNDYzMi04NzJlLTdiYTRlYmFjZjIyOSIsImIwYmViNjhhLTEyMDQtNGZlNy1iYTkwLTBjODRiMjQxNDBmNCJdfQ.p3B4s3L2yQr-0knnA5lAfU3Lpf_sK2H0YHv4zTDXoNdUfwzDtkgdeuhv73j9_9AVfqHk2rlcmns3iDQ0duwvNYFKTY4oMpUqrDIXPVRqE4icVIeVHDGvA5AFzge6fnY5-TPXQBgQhK0Wy9LUVqBlhP72aAcki3GE-XR4uaaYQUfCSNP4MNdehMvIp2Mm9VF9VWInA1cwvxmaAqZCuCLySGERj6v_4ptkW63vrdlzoKtUC52e-Q5Zk_plEaMo4iwvbOlABO63jBi1KmJNjR3HKSFW8zqEuW7tWimEfFAAhrrmENVSKjhZ-8h03MoH4YxfGqkTWxYz36HeVz9SCxkaCA" --iss="http://localhost" | jq -r .
{
  "aud": "adrianosela/all",
  "exp": 1508713061,
  "jti": "3f3ca91f-5a9a-450f-b441-9f629abb2f1b",
  "iat": 1508709461,
  "iss": "http://localhost",
  "nbf": 1508709461,
  "sub": "b49b56d6-43c0-4685-bc49-1062aa4bb7a9",
  "grps": [
    "c577690b-cb74-432b-9d05-f77803bfe425",
    "27d489ab-41e5-4632-872e-7ba4ebacf229",
    "b0beb68a-1204-4fe7-ba90-0c84b24140f4"
  ]
}
```

### A word about Private/Public Key-Pairs and their lifecyle:
Private keys are rotated every day (if its ran for a day, that is) and their lifecycle is as follows:
 * Private/public key-pair is generated and saved in memory (i.e. in a struct)
 * The key-pair has to be written somewhere in case the program fails (otherwise it can't be recovered), therefore it is stored in DynamoDB in order to avoid having the private key in the file system of the host, which could be compromised 
 * The Key Pair is used for signing and verifying tokens which (say) have a lifetime of 12 hours. That means we must be able to verify tokens signed with a private key that is no longer used to sign tokens, thus we need to keep the public key around for 12 hours after the private key is pruned.
 * So at any given time we will have a key-pair that can still sign and verify and one key-pair that can only verify tokens

### Example response of OpenID Connect Confiuration discovery Endpoint:
```
$ http http://localhost/.well-known/webfinder | jq -r .
{
  "issuer": "http://localhost",
  "authorization_endpoint": "http://localhost/auth",
  "token_endpoint": "http://localhost/auth/token",
  "userinfo_endpoint": "http://localhost/auth/userinfo",
  "registration_endpoint": "",
  "jwks_uri": "http://localhost/keys",
  "claims_parameter_supported": false,
  "scopes_supported": [
    "openid"
  ],
  "response_types_supported": [
    "code",
    "id_token",
    "token id_token"
  ],
  "response_modes_supported": [
    "query",
    "fragment"
  ],
  "grant_types_supported": [
    "refresh_token"
  ],
  "subject_types_supported": [
    "pairwise"
  ],
  "id_token_signing_alg_values_supported": [
    "RS512"
  ],
  "token_endpoint_auth_methods_supported": [
    "client_secret_basic"
  ],
  "token_endpoint_auth_signing_alg_values_supported": [
    "RS512"
  ],
  "claims_supported": [
    "aud",
    "exp",
    "jti",
    "iat",
    "iss",
    "sub",
    "grps"
  ]
}
```
