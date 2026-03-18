package co.ferrells.compositetrustmanager.autoconfigure;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("composite-trust-manager")
public class CompositeTrustManagerProperties {

    /**
     * Enables the auto-configuration.
     */
    private boolean enabled = true;

    /**
     * Name of the existing Spring Boot SSL bundle to union with the JVM trust store.
     */
    // @TODO array to allow multiple bundles?
    private String bundle;

    /**
     * Whether to pre-configure the standard Spring Boot HTTP client builders.
     */
    private boolean configureHttpClients = true;

    /**
     * Whether to install the composite SSLContext as the JVM default.
     */
    private boolean installDefaultSslContext = true;

    /**
     * Whether to ignore mis-matched hostnames, <em>only affects certificates in Spring's {@code SslBundle}</em>.
     * <p>
     * Common with embedded devices and consumer products on a LAN.<br>
     * i.e. routers, modems, NASes, etc...
     */
    private boolean ignoreHostnameMismatch = false;

    /**
     * Whether to configure Spring LDAP TLS authentication strategies with the composite
     * SSL socket factory.
     * <p>
     * Covers STARTTLS connections independently of
     * install-default-ssl-context. Has no effect when spring-ldap-core is not present.
     */
    private boolean configureLdap = true;

    public boolean isEnabled() {
        return this.enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getBundle() {
        return this.bundle;
    }

    public void setBundle(String bundle) {
        this.bundle = bundle;
    }

    public boolean isConfigureHttpClients() {
        return this.configureHttpClients;
    }

    public void setConfigureHttpClients(boolean configureHttpClients) {
        this.configureHttpClients = configureHttpClients;
    }

    public boolean isInstallDefaultSslContext() {
        return this.installDefaultSslContext;
    }

    public void setInstallDefaultSslContext(boolean installDefaultSslContext) {
        this.installDefaultSslContext = installDefaultSslContext;
    }

    public boolean isIgnoreHostnameMismatch() {
        return this.ignoreHostnameMismatch;
    }

    public void setIgnoreHostnameMismatch(boolean ignoreHostnameMismatch) {
        this.ignoreHostnameMismatch = ignoreHostnameMismatch;
    }

    public boolean isConfigureLdap() {
        return this.configureLdap;
    }

    public void setConfigureLdap(boolean configureLdap) {
        this.configureLdap = configureLdap;
    }

}
