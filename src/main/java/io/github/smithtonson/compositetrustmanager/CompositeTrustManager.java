package io.github.smithtonson.compositetrustmanager;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.springframework.boot.ssl.SslBundle;
import org.springframework.util.Assert;

/**
 * {@link X509TrustManager} that unions the JVM's system trust managers with the
 * trust managers from a configured Spring Boot {@link SslBundle}.
 */
public class CompositeTrustManager implements X509TrustManager {

    public static final Logger LOG = Logger.getLogger("io.github.smithtonson.CompositeTrustManager"); //NOI18N
    private final List<X509TrustManager> delegates;

    public CompositeTrustManager(List<X509TrustManager> delegates) {
        Assert.notEmpty(delegates, "At least one X509TrustManager is required");
        this.delegates = List.copyOf(delegates);
    }

    /**
     * Builder using a provided {@link SslBundle}
     *
     * @param sslBundle
     *
     * @return new CompositeTrustManager
     */
    public static CompositeTrustManager fromSystemAndBundle(SslBundle sslBundle) {
        Assert.notNull(sslBundle, "SslBundle must not be null");
        List<X509TrustManager> trustManagers = new ArrayList<>();
        trustManagers.addAll(getDefaultTrustManagers());
        trustManagers.addAll(extractX509TrustManagers(sslBundle.getManagers().getTrustManagers()));

        return new CompositeTrustManager(trustManagers);
    }

    public static List<X509TrustManager> getDefaultTrustManagers() {
        try {
            TrustManagerFactory trustFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustFactory.init(loadDefaultTrustStore());

            return extractX509TrustManagers(trustFactory.getTrustManagers());
        }
        catch (KeyStoreException | NoSuchAlgorithmException ex) {
            throw new IllegalStateException("Unable to load the JVM default trust managers", ex);
        }
    }

    public static List<X509TrustManager> extractX509TrustManagers(TrustManager[] trustManagers) {
        Assert.notNull(trustManagers, "TrustManager array must not be null");

        List<X509TrustManager> x509TrustManagers = Arrays.stream(trustManagers)
                .filter(X509TrustManager.class::isInstance)
                .map(X509TrustManager.class::cast)
                .toList();

        if (x509TrustManagers.isEmpty()) {
            throw new IllegalStateException("No X509TrustManager instances were available");
        }

        return x509TrustManagers;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        CertificateException lastFailure = null;

        for (X509TrustManager trustManager : this.delegates) {
            try {
                trustManager.checkClientTrusted(chain, authType);
                return;
            }
            catch (CertificateException e) {
                lastFailure = e;
            }
            catch (RuntimeException e) {
                lastFailure = new CertificateException("Trust manager threw unexpected exception", e);
            }
        }

        throw new CertificateException("No configured TrustManagers trust this client certificate chain", lastFailure);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        CertificateException lastFailure = null;
        
        for (X509TrustManager trustManager : this.delegates) {
            try {
                trustManager.checkServerTrusted(chain, authType);
                return;
            }
            catch (CertificateException e) {
                lastFailure = e;
            }
            catch (RuntimeException e) {
                lastFailure = new CertificateException("Trust manager threw unexpected exception", e);
            }
        }

        throw new CertificateException("No configured TrustManagers trust this server certificate chain", lastFailure);
    }

    /**
     * Union all Accepted Issuers from all TrustManager delegates.<br>
     * {@inheritDoc}
     *
     * @return a non-null (possibly empty) array of acceptable CA issuer certificates.
     * 
     * @see javax.net.ssl.X509TrustManager#getAcceptedIssuers()
     */
    @Override
    public X509Certificate[] getAcceptedIssuers() {
        Set<X509Certificate> issuers = new LinkedHashSet<>();
        for (X509TrustManager trustManager : this.delegates) {
            issuers.addAll(Arrays.asList(trustManager.getAcceptedIssuers()));
        }

        return issuers.toArray(X509Certificate[]::new);
    }

    /**
     * Load JVM's system-default TrustStore as configured in
     * <code>javax.net.ssl.trustStore</code> System Property.
     *
     * @return KeyStore the system default keystore
     *
     * @throws IllegalStateException Trust store can't be loaded
     */
    public static KeyStore loadDefaultTrustStore() {
        final String type = resolveTrustStoreType();
        
        try {
            KeyStore trustStore = KeyStore.getInstance(type);
            String configured = System.getProperty("javax.net.ssl.trustStore");

            // "NONE" is a special JVM value meaning no file-based trust store;
            // load with null to produce an empty in-memory store backed by the
            // security provider defaults.
            if ("NONE".equals(configured)) {
                trustStore.load(null, null);

                return trustStore;
            }

            Path location = resolveTrustStoreLocation(configured);
            char[] password = resolveTrustStorePassword(); // char[] so the password doesn't sit on the heap... (is this needed?)
            try {
                try (var inputStream = Files.newInputStream(location)) {
                    trustStore.load(inputStream, password);
                }
            }
            finally {
                Arrays.fill(password, '\0'); // clear password out of memory ASAP (is this still needed in modern Java?)
            }

            return trustStore;
        }
        catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException ex) {
            throw new IllegalStateException("Unable to load the JVM default trust store", ex);
        }
    }

    public static Path resolveTrustStoreLocation(String configured) {
        if (configured != null && !configured.isBlank()) {
            Path candidate = Paths.get(configured);
            File file = candidate.toFile();
            
            if (!file.exists() || !file.isFile() || !file.canRead()) {
                throw new IllegalStateException("Configured trust store does not exist or is not readable: " + configured);
            }
            
            return candidate;
        }

        Path jssecacerts = Paths.get(System.getProperty("java.home"), "lib", "security", "jssecacerts");
        if (Files.isReadable(jssecacerts)) {
            return jssecacerts;
        }

        Path cacerts = Paths.get(System.getProperty("java.home"), "lib", "security", "cacerts");
        if (Files.isReadable(cacerts)) {
            return cacerts;
        }

        throw new IllegalStateException("Unable to locate the JVM default trust store");
    }

    public static char[] resolveTrustStorePassword() {
        String configured = System.getProperty("javax.net.ssl.trustStorePassword");
        return (configured != null && !configured.isBlank()) ? configured.toCharArray() : "changeit".toCharArray(); // "changeit" is JVMs default TrustStore password
    }

    public static String resolveTrustStoreType() {
        String configured = System.getProperty("javax.net.ssl.trustStoreType");
        return (configured != null && !configured.isBlank()) ? configured : KeyStore.getDefaultType();
    }

}
