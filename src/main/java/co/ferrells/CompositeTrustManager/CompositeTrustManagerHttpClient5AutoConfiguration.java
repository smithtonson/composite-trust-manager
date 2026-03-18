package co.ferrells.CompositeTrustManager;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;

import org.apache.hc.client5.http.ssl.DefaultClientTlsStrategy;
import org.apache.hc.client5.http.ssl.TlsSocketStrategy;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;

/**
 * Auto-configuration that exposes a composite {@link TlsSocketStrategy} for use
 * with Apache HttpClient 5 ({@code httpclient5}).
 * <p>
 * Apache HttpClient 5 calls {@code SSLContexts.createSystemDefault()} internally when
 * building a {@code CloseableHttpClient}, which reads the JVM trust store directly and
 * bypasses {@code SSLContext.getDefault()}. This means the composite trust manager is
 * <em>not</em> applied to manually constructed {@code CloseableHttpClient} beans, even
 * when {@code install-default-ssl-context} is {@code true}.
 * <p>
 * This auto-configuration exposes a {@link TlsSocketStrategy} bean backed by
 * {@link DefaultClientTlsStrategy} and pre-configured with the composite {@link SSLContext}.
 * Inject it when building a {@code CloseableHttpClient} manually see the README
 * "Known issues" section for a usage example.
 * <p>
 * This class is separate from {@link CompositeTrustManagerAutoConfiguration} so that
 * {@code @ConditionalOnBean} on the {@code @Bean} method is evaluated after the parent
 * auto-configuration's beans are registered. Class-level {@code @ConditionalOnBean} across
 * auto-configuration boundaries is unreliable - see the inline comment on this class.
 */
// @ConditionalOnBean is intentionally placed on the @Bean method rather than the class.
// Class-level @ConditionalOnBean across auto-configuration boundaries is unreliable in testing:
// Spring evaluates it during configuration class scanning, before the peer auto-configuration's
// bean definitions are guaranteed to be visible, even with @AutoConfiguration(after = ...) ordering.
@AutoConfiguration(after = CompositeTrustManagerAutoConfiguration.class)
@ConditionalOnClass(DefaultClientTlsStrategy.class)
@ConditionalOnProperty(prefix = "composite-trust-manager", name = "configure-http-clients", havingValue = "true", matchIfMissing = true)
public class CompositeTrustManagerHttpClient5AutoConfiguration {

    static final String TLS_STRATEGY_BEAN_NAME = "compositeTrustManagerTlsStrategy";

    @Bean(name = TLS_STRATEGY_BEAN_NAME)
    @ConditionalOnBean(name = CompositeTrustManagerAutoConfiguration.SSL_CONTEXT_BEAN_NAME)
    TlsSocketStrategy compositeTrustManagerTlsStrategy(
            @Qualifier(CompositeTrustManagerAutoConfiguration.SSL_CONTEXT_BEAN_NAME) SSLContext sslContext,
            CompositeTrustManagerProperties properties) 
    {
        // When ignore-hostname-mismatch is enabled, use the bundle-aware verifier so that
        // certificates only trusted by the SSL bundle (e.g. devices with no SANs) skip
        // hostname verification, while public CA-signed certs are still checked strictly.
        if (properties.isIgnoreHostnameMismatch()) {
            HostnameVerifier bundleAwareVerifier = new BundleAwareHostnameVerifier(
                    CompositeTrustManager.getDefaultTrustManagers(),
                    org.apache.hc.client5.http.ssl.HttpsSupport.getDefaultHostnameVerifier());
            
            return new DefaultClientTlsStrategy(sslContext, bundleAwareVerifier);
        }
        
        return new DefaultClientTlsStrategy(sslContext);
    }

}
