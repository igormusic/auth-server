# Authorization Server

Based on [Spring Authorization Server](https://github.com/spring-projects/spring-authorization-server) this implementation primarily focuses on client credential OAuth flow.

You can configure multiple clients in the configuration file:

```
auth-server.cert-path = src/main/resources/dev.pfx
auth-server.cert-password = devpass
auth-server.clients[0].id = test-client-1
auth-server.clients[0].password = secret-1
auth-server.clients[1].id = test-client-2
auth-server.clients[1].password = secret-2
```

PFX file is required for public/private key required to sign and validate JWT tokens.

Running the application:

`mvn spring-boot:run`

Configuration is accessible from [http://localhost:8080/.well-known/openid-configuration](http://localhost:8080/.well-known/openid-configuration)

Here is sample of retrieving OAuth token using client credentials flow:

```
curl -X POST \
  http://localhost:8080/oauth2/token \
  -H 'cache-control: no-cache' \
  -H 'content-type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials&client_id=test-client-1&client_secret=secret-1'
```
