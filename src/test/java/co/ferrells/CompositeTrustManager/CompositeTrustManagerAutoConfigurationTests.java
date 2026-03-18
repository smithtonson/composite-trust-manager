package co.ferrells.CompositeTrustManager;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import org.apache.hc.client5.http.ssl.TlsSocketStrategy;

import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.http.HttpMessageConvertersAutoConfiguration;
import org.springframework.boot.autoconfigure.http.client.HttpClientAutoConfiguration;
import org.springframework.boot.autoconfigure.http.client.reactive.ClientHttpConnectorAutoConfiguration;
import org.springframework.boot.autoconfigure.ssl.SslAutoConfiguration;
import org.springframework.boot.autoconfigure.web.client.RestClientAutoConfiguration;
import org.springframework.boot.autoconfigure.web.client.RestTemplateAutoConfiguration;
import org.springframework.boot.autoconfigure.web.reactive.function.client.WebClientAutoConfiguration;
import org.springframework.boot.http.client.ClientHttpRequestFactorySettings;
import org.springframework.boot.http.client.reactive.ClientHttpConnectorSettings;
import org.springframework.boot.ssl.DefaultSslBundleRegistry;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslStoreBundle;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.ldap.core.support.DefaultTlsDirContextAuthenticationStrategy;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;

import static org.assertj.core.api.Assertions.assertThat;

class CompositeTrustManagerAutoConfigurationTests {

    private static final char[] STORE_PASSWORD = "password".toCharArray();

    private final SSLContext originalDefaultContext = defaultSslContext();

    private final javax.net.ssl.SSLSocketFactory originalDefaultSocketFactory = HttpsURLConnection
            .getDefaultSSLSocketFactory();

    private final HostnameVerifier originalDefaultHostnameVerifier = HttpsURLConnection
            .getDefaultHostnameVerifier();

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    SslAutoConfiguration.class,
                    HttpMessageConvertersAutoConfiguration.class,
                    HttpClientAutoConfiguration.class,
                    ClientHttpConnectorAutoConfiguration.class,
                    CompositeTrustManagerAutoConfiguration.class,
                    CompositeTrustManagerLdapAutoConfiguration.class,
                    CompositeTrustManagerHttpClient5AutoConfiguration.class,
                    RestTemplateAutoConfiguration.class,
                    RestClientAutoConfiguration.class,
                    WebClientAutoConfiguration.class))
            .withBean(DefaultSslBundleRegistry.class, CompositeTrustManagerAutoConfigurationTests::sslBundleRegistry)
            .withPropertyValues("composite-trust-manager.bundle=test");

    @AfterEach
    void restoreDefaultSslContext() {
        SSLContext.setDefault(this.originalDefaultContext);
        HttpsURLConnection.setDefaultSSLSocketFactory(this.originalDefaultSocketFactory);
        HttpsURLConnection.setDefaultHostnameVerifier(this.originalDefaultHostnameVerifier);
    }

    @Test
    void installsCompositeBundleAndGlobalSslDefaultsForNonBootTlsClients() throws Exception {
        try (TestHttpsServer server = TestHttpsServer.start()) {
            this.contextRunner.run((context) -> {
                SslBundle composite = context.getBean(CompositeTrustManagerAutoConfiguration.SSL_BUNDLE_BEAN_NAME,
                        SslBundle.class);
                SSLContext sslContext = context.getBean(CompositeTrustManagerAutoConfiguration.SSL_CONTEXT_BEAN_NAME,
                        SSLContext.class);

                assertThat(composite).isNotNull();
                assertThat(sslContext).isSameAs(SSLContext.getDefault());
                assertThat(readWithHttpsURLConnection(server.uri())).isEqualTo("ok");
            });
        }
    }

    @Test
    void configuresStandardHttpClientBuildersToUseCompositeTrustAutomatically() throws Exception {
        try (TestHttpsServer server = TestHttpsServer.start()) {
            this.contextRunner
                    .withPropertyValues("composite-trust-manager.install-default-ssl-context=false")
                    .run((context) -> {
                        SslBundle composite = context.getBean(CompositeTrustManagerAutoConfiguration.SSL_BUNDLE_BEAN_NAME,
                                SslBundle.class);
                        ClientHttpRequestFactorySettings servletSettings = context.getBean(ClientHttpRequestFactorySettings.class);
                        ClientHttpConnectorSettings reactiveSettings = context.getBean(ClientHttpConnectorSettings.class);

                        RestTemplate restTemplate = context.getBean(RestTemplateBuilder.class)
                                .connectTimeout(Duration.ofSeconds(5))
                                .readTimeout(Duration.ofSeconds(5))
                                .build();
                        ClientHttpRequestFactory requestFactory = restTemplate.getRequestFactory();

                        RestClient restClient = context.getBean(RestClient.Builder.class)
                                .build();

                        WebClient webClient = context.getBean(WebClient.Builder.class)
                                .build();

                        assertThat(servletSettings.sslBundle()).isSameAs(composite);
                        assertThat(reactiveSettings.sslBundle()).isSameAs(composite);
                        assertThat(requestFactory).isNotNull();

                        assertThat(restTemplate.getForObject(server.uri(), String.class)).isEqualTo("ok");
                        assertThat(restClient.get().uri(server.uri()).retrieve().body(String.class)).isEqualTo("ok");
                        assertThat(webClient.get()
                                .uri(server.uri())
                                .retrieve()
                                .bodyToMono(String.class)
                                .block(Duration.ofSeconds(5))).isEqualTo("ok");
                    });
        }
    }

    @Test
    void configuresStartTlsAuthenticationStrategyWithCompositeSslSocketFactory() {
        this.contextRunner
                .withPropertyValues("composite-trust-manager.install-default-ssl-context=false")
                .withBean(DefaultTlsDirContextAuthenticationStrategy.class)
                .run((context) -> {
                    assertThat(context).hasNotFailed();
                    SSLSocketFactory compositeSocketFactory = context.getBean(
                            CompositeTrustManagerAutoConfiguration.SSL_SOCKET_FACTORY_BEAN_NAME,
                            SSLSocketFactory.class);
                    DefaultTlsDirContextAuthenticationStrategy strategy = context
                            .getBean(DefaultTlsDirContextAuthenticationStrategy.class);

                    SSLSocketFactory strategySocketFactory = extractField(strategy, SSLSocketFactory.class);

                    assertThat(strategySocketFactory).isSameAs(compositeSocketFactory);
                });
    }

    @Test
    void doesNotConfigureStartTlsAuthenticationStrategyWhenConfigureLdapIsDisabled() {
        this.contextRunner
                .withPropertyValues("composite-trust-manager.configure-ldap=false")
                .withBean(DefaultTlsDirContextAuthenticationStrategy.class)
                .run((context) -> {
                    DefaultTlsDirContextAuthenticationStrategy strategy = context
                            .getBean(DefaultTlsDirContextAuthenticationStrategy.class);
                    SSLSocketFactory strategySocketFactory = extractField(strategy, SSLSocketFactory.class);
                    assertThat(strategySocketFactory).isNull();
                });
    }

    @Test
    void exposesHttpClient5TlsStrategyWhenHttpClient5IsPresent() {
        this.contextRunner.run((context) -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasBean(
                    CompositeTrustManagerHttpClient5AutoConfiguration.TLS_STRATEGY_BEAN_NAME);
            TlsSocketStrategy tlsStrategy = context.getBean(
                    CompositeTrustManagerHttpClient5AutoConfiguration.TLS_STRATEGY_BEAN_NAME,
                    TlsSocketStrategy.class);
            assertThat(tlsStrategy).isNotNull();
        });
    }

    @Test
    void doesNotExposeHttpClient5TlsStrategyWhenConfigureHttpClientsIsDisabled() {
        this.contextRunner
                .withPropertyValues("composite-trust-manager.configure-http-clients=false")
                .run((context) -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean(
                            CompositeTrustManagerHttpClient5AutoConfiguration.TLS_STRATEGY_BEAN_NAME);
                });
    }

    @Test
    void doesNotInstallBundleAwareHostnameVerifierByDefault() {
        this.contextRunner.run((context) -> {
            assertThat(context).hasNotFailed();
            assertThat(context).doesNotHaveBean(
                    CompositeTrustManagerAutoConfiguration.HOSTNAME_VERIFIER_BEAN_NAME);
            assertThat(HttpsURLConnection.getDefaultHostnameVerifier())
                    .isNotInstanceOf(BundleAwareHostnameVerifier.class);
        });
    }

    @Test
    void exposesBundleAwareHostnameVerifierWhenIgnoreHostnameMismatchEnabled() {
        this.contextRunner
                .withPropertyValues("composite-trust-manager.ignore-hostname-mismatch=true")
                .run((context) -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasBean(
                            CompositeTrustManagerAutoConfiguration.HOSTNAME_VERIFIER_BEAN_NAME);
                    HostnameVerifier verifier = context.getBean(
                            CompositeTrustManagerAutoConfiguration.HOSTNAME_VERIFIER_BEAN_NAME,
                            HostnameVerifier.class);
                    assertThat(verifier).isInstanceOf(BundleAwareHostnameVerifier.class);
                });
    }

    @Test
    void installsBundleAwareHostnameVerifierAsGlobalDefaultWhenIgnoreHostnameMismatchEnabled() {
        this.contextRunner
                .withPropertyValues("composite-trust-manager.ignore-hostname-mismatch=true")
                .run((context) -> {
                    assertThat(context).hasNotFailed();
                    assertThat(HttpsURLConnection.getDefaultHostnameVerifier())
                            .isInstanceOf(BundleAwareHostnameVerifier.class);
                });
    }

    @Test
    void httpclient5TlsStrategyUsesBundleAwareVerifierWhenIgnoreHostnameMismatchEnabled() {
        this.contextRunner
                .withPropertyValues("composite-trust-manager.ignore-hostname-mismatch=true")
                .run((context) -> {
                    assertThat(context).hasNotFailed();
                    TlsSocketStrategy tlsStrategy = context.getBean(
                            CompositeTrustManagerHttpClient5AutoConfiguration.TLS_STRATEGY_BEAN_NAME,
                            TlsSocketStrategy.class);
                    assertThat(tlsStrategy).isNotNull();
                    // Verify the strategy has the bundle-aware verifier via field inspection
                    HostnameVerifier verifier = extractField(tlsStrategy, HostnameVerifier.class);
                    assertThat(verifier).isInstanceOf(BundleAwareHostnameVerifier.class);
                });
    }

    private static <T> T extractField(Object target, Class<T> type) {
        Class<?> current = target.getClass();
        while (current != null) {
            for (var field : current.getDeclaredFields()) {
                if (type.isAssignableFrom(field.getType())) {
                    field.setAccessible(true);
                    try {
                        return type.cast(field.get(target));
                    }
                    catch (IllegalAccessException ex) {
                        throw new IllegalStateException(ex);
                    }
                }
            }
            current = current.getSuperclass();
        }
        return null;
    }

    private static String readWithHttpsURLConnection(URI uri) {
        try {
            HttpsURLConnection connection = (HttpsURLConnection) new URL(uri.toString()).openConnection();
            connection.setConnectTimeout(5_000);
            connection.setReadTimeout(5_000);
            try (InputStream inputStream = connection.getInputStream()) {
                return new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
            }
        }
        catch (IOException ex) {
            throw new IllegalStateException("Failed to read HTTPS response from " + uri, ex);
        }
    }

    private static DefaultSslBundleRegistry sslBundleRegistry() {
        DefaultSslBundleRegistry registry = new DefaultSslBundleRegistry();
        registry.registerBundle("test", testSslBundle());
        return registry;
    }

    private static SslBundle testSslBundle() {
        return SslBundle.of(SslStoreBundle.of(null, null, loadKeyStore("tls/client-truststore.p12")));
    }

    private static KeyStore loadKeyStore(String resourcePath) {
        try (InputStream inputStream = CompositeTrustManagerAutoConfigurationTests.class.getClassLoader()
                .getResourceAsStream(resourcePath)) {
            assertThat(inputStream).as("Missing test resource %s", resourcePath).isNotNull();
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(inputStream, STORE_PASSWORD);
            return keyStore;
        }
        catch (Exception ex) {
            throw new IllegalStateException("Failed to load key store " + resourcePath, ex);
        }
    }

    private static SSLContext defaultSslContext() {
        try {
            return SSLContext.getDefault();
        }
        catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static final class TestHttpsServer implements AutoCloseable {

        private final HttpsServer server;

        private TestHttpsServer(HttpsServer server) {
            this.server = server;
        }

        static TestHttpsServer start() {
            try {
                KeyStore keyStore = loadKeyStore("tls/server-keystore.p12");

                KeyManagerFactory keyManagerFactory = KeyManagerFactory
                        .getInstance(KeyManagerFactory.getDefaultAlgorithm());
                keyManagerFactory.init(keyStore, STORE_PASSWORD);

                SSLContext sslContext = SSLContext.getInstance("TLS");
                sslContext.init(keyManagerFactory.getKeyManagers(), null, null);

                HttpsServer server = HttpsServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
                server.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
                    @Override
                    public void configure(HttpsParameters params) {
                        params.setSSLParameters(getSSLContext().getDefaultSSLParameters());
                    }
                });
                server.createContext("/", exchange -> {
                    byte[] response = "ok".getBytes(StandardCharsets.UTF_8);
                    exchange.sendResponseHeaders(200, response.length);
                    exchange.getResponseBody().write(response);
                    exchange.close();
                });
                server.start();
                return new TestHttpsServer(server);
            }
            catch (Exception ex) {
                throw new IllegalStateException("Failed to start HTTPS test server", ex);
            }
        }

        URI uri() {
            return URI.create("https://localhost:" + this.server.getAddress().getPort() + "/");
        }

        @Override
        public void close() {
            this.server.stop(0);
        }

    }

}
