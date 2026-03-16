package co.ferrells.CompositeTrustManager;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.ssl.SslAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.http.client.ClientHttpRequestFactorySettings;
import org.springframework.boot.http.client.reactive.ClientHttpConnectorSettings;
import org.springframework.context.annotation.Primary;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.Assert;

// afterName/beforeName (string form) is used instead of after/before (class references) for all
// optional auto-configuration classes. Using class references in @AutoConfiguration(after/before=...)
// forces Spring to classload them during bean name generation — before any @ConditionalOnClass checks
// run — which causes an IllegalArgumentException in projects that don't have those classes on the
// classpath.
//
// String-based afterName/beforeName tolerates missing classes gracefully.
// Affected classes and the dependency that provides them:
//   HttpClientAutoConfiguration              – spring-boot-autoconfigure 3.4+
//   ClientHttpConnectorAutoConfiguration     – spring-boot-autoconfigure 3.4+
//   RestTemplateAutoConfiguration            – spring-web
//   RestClientAutoConfiguration              – spring-web
//   WebClientAutoConfiguration               – spring-webflux
//
// SslAutoConfiguration is declared as a class reference (not string) because it is in
// spring-boot-autoconfigure, which is a required dependency. It must appear in after= so that
// SslBundles is registered before our @ConditionalOnBean(SslBundles.class) is evaluated.
@AutoConfiguration(
        after = SslAutoConfiguration.class,
        afterName = {
            "org.springframework.boot.autoconfigure.http.client.HttpClientAutoConfiguration",
            "org.springframework.boot.autoconfigure.http.client.reactive.ClientHttpConnectorAutoConfiguration"
        },
        beforeName = {
            "org.springframework.boot.autoconfigure.web.client.RestTemplateAutoConfiguration",
            "org.springframework.boot.autoconfigure.web.client.RestClientAutoConfiguration",
            "org.springframework.boot.autoconfigure.web.reactive.function.client.WebClientAutoConfiguration"
        })
@EnableConfigurationProperties(CompositeTrustManagerProperties.class)
@ConditionalOnClass(SslBundles.class)
@ConditionalOnProperty(prefix = "composite-trust-manager", name = "enabled", havingValue = "true", matchIfMissing = true)
public class CompositeTrustManagerAutoConfiguration {

    static final String SSL_BUNDLE_BEAN_NAME = "compositeTrustManagerSslBundle";
    static final String SSL_CONTEXT_BEAN_NAME = "compositeTrustManagerSslContext";
    static final String SSL_SOCKET_FACTORY_BEAN_NAME = "compositeTrustManagerSslSocketFactory";

    @Bean(name = SSL_BUNDLE_BEAN_NAME)
    @ConditionalOnBean(SslBundles.class)
    @ConditionalOnProperty(prefix = "composite-trust-manager", name = "bundle")
    SslBundle compositeTrustManagerSslBundle(SslBundles sslBundles, CompositeTrustManagerProperties properties) {
        Assert.hasText(properties.getBundle(),
                "The property 'composite-trust-manager.bundle' must reference an existing Spring Boot SSL bundle");
        return CompositeTrustManagerSslBundle.create(sslBundles.getBundle(properties.getBundle()));
    }

    @Bean(name = SSL_CONTEXT_BEAN_NAME)
    @ConditionalOnBean(name = SSL_BUNDLE_BEAN_NAME)
    SSLContext compositeTrustManagerSslContext(@Qualifier(SSL_BUNDLE_BEAN_NAME) SslBundle sslBundle) {
        return sslBundle.createSslContext();
    }

    @Bean(name = SSL_SOCKET_FACTORY_BEAN_NAME)
    @ConditionalOnBean(name = SSL_CONTEXT_BEAN_NAME)
    SSLSocketFactory compositeTrustManagerSslSocketFactory(
            @Qualifier(SSL_CONTEXT_BEAN_NAME) SSLContext sslContext) {
        return sslContext.getSocketFactory();
    }

    @Bean
    @ConditionalOnBean(name = SSL_CONTEXT_BEAN_NAME)
    @ConditionalOnProperty(prefix = "composite-trust-manager", name = "install-default-ssl-context", havingValue = "true", matchIfMissing = true)
    InitializingBean compositeTrustManagerGlobalSslDefaults(
            @Qualifier(SSL_SOCKET_FACTORY_BEAN_NAME) SSLSocketFactory sslSocketFactory,
            @Qualifier(SSL_CONTEXT_BEAN_NAME) SSLContext sslContext){
        return () -> {
            SSLContext.setDefault(sslContext);
            HttpsURLConnection.setDefaultSSLSocketFactory(sslSocketFactory);
        };
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnBean(name = "clientHttpRequestFactorySettings")
    @ConditionalOnProperty(prefix = "composite-trust-manager", name = "bundle")
    @ConditionalOnProperty(prefix = "composite-trust-manager", name = "configure-http-clients", havingValue = "true", matchIfMissing = true)
    static class ServletHttpClientConfiguration {

        @Bean
        @Primary
        @ConditionalOnClass(ClientHttpRequestFactorySettings.class)
        ClientHttpRequestFactorySettings compositeTrustManagerClientHttpRequestFactorySettings(
                @Qualifier("clientHttpRequestFactorySettings") ClientHttpRequestFactorySettings settings,
                @Qualifier(SSL_BUNDLE_BEAN_NAME) SslBundle sslBundle) {
            return settings.withSslBundle(sslBundle);
        }

    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnBean(name = "clientHttpConnectorSettings")
    @ConditionalOnProperty(prefix = "composite-trust-manager", name = "bundle")
    @ConditionalOnProperty(prefix = "composite-trust-manager", name = "configure-http-clients", havingValue = "true", matchIfMissing = true)
    static class ReactiveHttpClientConfiguration {

        @Bean
        @Primary
        @ConditionalOnClass(ClientHttpConnectorSettings.class)
        ClientHttpConnectorSettings compositeTrustManagerClientHttpConnectorSettings(
                @Qualifier("clientHttpConnectorSettings") ClientHttpConnectorSettings settings,
                @Qualifier(SSL_BUNDLE_BEAN_NAME) SslBundle sslBundle) {
            return settings.withSslBundle(sslBundle);
        }

    }

}
