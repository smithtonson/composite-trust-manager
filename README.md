# CompositeTrustManager

`CompositeTrustManager` is a Spring Boot autoconfiguration library that unions the JVM/system trust store with the trust material from a named Spring Boot SSL bundle.

This lets a consuming application trust both:

- the normal public root CAs already available to the JVM
- private or self-signed certificates defined by the application

It preserves normal certificate validation instead of replacing it with a permissive "trust all" implementation.

## Why use this in addition to Spring Boot's SSL bundles?

Boot's built-in SSL bundles let you configure custom certificates, but they
**replace** the JVM's default trust store — your app loses trust in all normal public CAs
unless you manually re-add them to the bundle or configure which SSL configuration to
use on a per-request or httpclient basis.

**Example:** your app needs to call both `https://api.github.com` (trusted by the JVM's
built-in root CAs) and `https://internal.corp` (a private CA or self-signed certificate).

With bare SSL bundles:
- Configuring a bundle with your private certificate means the bundle's trust store only
  knows about that certificate — calls to `api.github.com` fail with an untrusted
  certificate error
- The workaround is to manually export all ~150 JVM root CAs into your trust store file
  and keep that file in sync as root CAs are added or removed over time or to
  manually add trusted certs to the system-wide trust store.

With this library:
- Configure a bundle with your private certificate and point the library at it — the
  library unions that bundle with the JVM's existing trust store automatically
- Both `api.github.com` and `internal.corp` are trusted with no manual CA management
- Increased protability and ease-of-use when deploying to containers

### App-wide configuration

The library also installs the composite context as the JVM-wide SSL default, so coverage
extends beyond Spring's HTTP clients to `HttpsURLConnection`, JNDI/LDAP, Java's built-in
`HttpClient`, and Apache HttpClient 5 — without wiring SSL configuration into each one
individually.

## Use

Add the dependency to your Spring Boot application:

```xml
<dependency>
  <groupId>co.ferrells</groupId>
  <artifactId>CompositeTrustManager</artifactId>
  <version>0.0.1-SNAPSHOT</version>
</dependency>
```

Then define a Spring Boot SSL bundle and point this library at it.

Example using a PEM trust bundle:

```yaml
spring:
  ssl:
    bundle:
      pem:
        internal-ca: 
          truststore:
            certificate: classpath:certs/internal-ca.pem

composite-trust-manager:
  bundle: internal-ca
```

That configuration tells the library to:

- load the existing JVM trust store
- load the `internal-ca` Spring Boot SSL bundle
- create a composite trust configuration that unions both trust sources
- install that composite SSL context as the JVM default
- preconfigure Boot-managed `RestTemplateBuilder`, `RestClient.Builder`, and `WebClient.Builder`

## Client usage

Boot-managed HTTP clients can be injected normally:

```java
@Service
class DownstreamClient {

    private final RestTemplate restTemplate;
    private final RestClient restClient;
    private final WebClient webClient;

    DownstreamClient(RestTemplateBuilder restTemplateBuilder,
            RestClient.Builder restClientBuilder,
            WebClient.Builder webClientBuilder)
    {
        this.restTemplate = restTemplateBuilder.build();
        this.restClient = restClientBuilder.build();
        this.webClient = webClientBuilder.build();
    }
}
```

Because the autoconfiguration installs the composite `SSLContext` as the JVM
default, non-Boot outbound TLS clients also pick it up. For example, LDAPS/JNDI
clients do not need to set `java.naming.ldap.factory.socket` explicitly just to
use the additional private CA:

```java
Hashtable<String, Object> env = new Hashtable<>();
env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
env.put(Context.PROVIDER_URL, "ldaps://directory.example.com:636");

DirContext context = new InitialDirContext(env);
```

If your application uses Spring LDAP with explicit STARTTLS (via an
`AbstractTlsDirContextAuthenticationStrategy` such as
`DefaultTlsDirContextAuthenticationStrategy`), the composite socket factory is
automatically set on any such strategy bean present in the context — no
additional configuration is needed:

```java
@Bean
DefaultTlsDirContextAuthenticationStrategy ldapAuthStrategy() {
    return new DefaultTlsDirContextAuthenticationStrategy();
}
```

### TLS coverage summary

When `install-default-ssl-context: true` (default), the library covers explicit
non-Spring TLS connections as well:

| Connection type                                                        | Covered? | Method |
|------------------------------------------------------------------------|----------|--------|
| `new URL("https://...").openConnection()`                              | Yes      | `HttpsURLConnection` uses `HttpsURLConnection.getDefaultSSLSocketFactory()`, which the library sets |
| `SSLSocketFactory.getDefault().createSocket(...)`                      | Yes      | Delegates to `SSLContext.getDefault()`, which the library replaces |
| Java 11+ `HttpClient.newHttpClient()`                                  | Yes      | Uses `SSLContext.getDefault()` when no context is explicitly passed |
| Spring `RestTemplate` / `RestClient` / `WebClient`                     | Yes      | Boot-managed builders are pre-configured with the composite SSL bundle |
| Apache HttpClient 5 — Boot-managed (via `RestTemplate` / `RestClient`) | Yes      | Uses the composite bundle through Boot's `ClientHttpRequestFactorySettings` |
| Apache HttpClient 5 — manually created `CloseableHttpClient`           | No       | Calls `SSLContexts.createSystemDefault()` internally, bypassing `SSLContext.getDefault()` — see Known issues |
| `SSLContext.getInstance("TLS")` (explicit new context)                 | No       | Creates an independent context, unaffected by `setDefault()` |
| `new Socket(...)` (plain, no TLS)                                      | n/a      | Not a TLS connection |

## Optional properties

The autoconfiguration is controlled by these properties:

```yaml
composite-trust-manager:
  enabled: true
  bundle: internal-ca
  configure-http-clients: true
  configure-ldap: true
  install-default-ssl-context: true
```

- `bundle` is required for the library to do any work.
- Set `configure-http-clients: false` if you only want the global JVM SSL defaults.
- Set `configure-ldap: false` to skip configuring Spring LDAP STARTTLS strategy beans.
- Set `install-default-ssl-context: false` if you only want the Boot HTTP client beans customized.

## Building this project

- Run the full test suite with `./mvnw test`
- Run one test class with `./mvnw -Dtest=CompositeTrustManagerAutoConfigurationTests test`
- Build the jar with `./mvnw package`

## Known issues

### Apache HttpClient 5 — manually created `CloseableHttpClient`

Apache HttpClient 5 calls `SSLContexts.createSystemDefault()` when building a
`CloseableHttpClient`, which reads the JVM trust store directly and bypasses
`SSLContext.getDefault()`. Manually created `CloseableHttpClient` beans are therefore
not covered by the composite trust manager, even when `install-default-ssl-context` is
`true`.

**Fix:** inject the `compositeTrustManagerTlsStrategy` bean (`TlsSocketStrategy`), which the
library exposes automatically when `httpclient5` is on the classpath:

```java
@Bean
CloseableHttpClient myHttpClient(
        TlsSocketStrategy compositeTrustManagerTlsStrategy)
{
    return HttpClients.custom()
            .setConnectionManager(
                    PoolingHttpClientConnectionManagerBuilder
                        .create()
                        .setTlsSocketStrategy(compositeTrustManagerTlsStrategy)
                        .build()
            ).build();
}
```

This bean is controlled by the `composite-trust-manager.configure-http-clients` property
(default `true`). Set it to `false` to suppress the bean if you manage the SSL context
entirely yourself.

### Self-signed certificate with missing or incorrect Subject Alternative Names

If you load a self-signed certificate via an SSL bundle but the certificate has no Subject
Alternative Names (SANs) — or the SANs don't include the IP address or hostname you're
connecting to — you will get an error like:

```
javax.net.ssl.SSLPeerUnverifiedException: Certificate for <192.168.1.1> doesn't match
any of the subject alternative names: []
```

This means the certificate was **loaded and trusted correctly** by the composite trust
manager, but TLS hostname verification (a separate step) rejected it because the server's
identity couldn't be confirmed.

**The correct fix** is to reissue the certificate with a proper SAN. For an IP address,
the certificate needs an IP SAN (`subjectAltName = IP:192.168.1.1`). Most modern TLS
clients ignore the CN field entirely and require SANs.

**If you own the server**, regenerate the certificate with the correct SAN.

**If you cannot change the certificate** (e.g. an embedded device or legacy appliance),
you can disable hostname verification for that specific `CloseableHttpClient` only.
This weakens TLS security and should be avoided if possible:

```java
@Bean
CloseableHttpClient myHttpClient(
        @Qualifier("compositeTrustManagerSslContext") SSLContext sslContext)
{
    TlsSocketStrategy tlsStrategy = new DefaultClientTlsStrategy(
            sslContext, NoopHostnameVerifier.INSTANCE); // dev/test only

    return HttpClients
            .custom()
            .setConnectionManager(
                    PoolingHttpClientConnectionManagerBuilder
                        .create()
                        .setTlsSocketStrategy(tlsStrategy)
                        .build()
            ).build();
}
```

Note that this bypasses hostname verification entirely for every request made by
this httpclient — it does **not** bypass certificate trust validation, which the
composite trust manager still enforces.
