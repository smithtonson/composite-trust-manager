package co.ferrells.compositetrustmanager.autoconfigure;

import javax.net.ssl.SSLSocketFactory;

import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.ldap.core.support.AbstractTlsDirContextAuthenticationStrategy;

/**
 * Auto-configuration that wires the composite SSL socket factory into any Spring LDAP
 * STARTTLS authentication strategies present in the application context.
 * <p>
 * This auto-configuration is separate from {@link CompositeTrustManagerAutoConfiguration}
 * so that it runs after that class's bean definitions are fully registered. Member
 * configuration classes are processed before their enclosing class's {@code @Bean} methods,
 * which means {@code @ConditionalOnBean} checks for beans defined in the outer class would
 * always fail if evaluated from an inner member class.
 * <p>
 * For {@code ldaps://} (implicit SSL), the JVM default {@code SSLContext} installed by
 * {@code composite-trust-manager.install-default-ssl-context} (default: true) already
 * provides full coverage. This class closes the remaining gap for explicit STARTTLS
 * connections, particularly when the global default SSL context override is disabled.
 */
// @ConditionalOnBean is intentionally placed on the @Bean method rather than the class.
// Class-level @ConditionalOnBean across auto-configuration boundaries is unreliable:
// Spring evaluates it during configuration class scanning, before the peer auto-configuration's
// bean definitions are guaranteed to be visible, even with @AutoConfiguration(after = ...) ordering.
@AutoConfiguration(after = CompositeTrustManagerAutoConfiguration.class)
@ConditionalOnClass(AbstractTlsDirContextAuthenticationStrategy.class)
@ConditionalOnProperty(prefix = "composite-trust-manager", name = "configure-ldap", havingValue = "true", matchIfMissing = true)
public class CompositeTrustManagerLdapAutoConfiguration {

    @Bean
    @ConditionalOnBean(name = CompositeTrustManagerAutoConfiguration.SSL_SOCKET_FACTORY_BEAN_NAME)
    SmartInitializingSingleton compositeTrustManagerLdapTlsConfigurer(
            @Qualifier(CompositeTrustManagerAutoConfiguration.SSL_SOCKET_FACTORY_BEAN_NAME) SSLSocketFactory sslSocketFactory,
            ListableBeanFactory beanFactory) 
    {
        return () -> beanFactory.getBeansOfType(AbstractTlsDirContextAuthenticationStrategy.class)
                .values()
                .forEach((strategy) -> strategy.setSslSocketFactory(sslSocketFactory));
    }

}
