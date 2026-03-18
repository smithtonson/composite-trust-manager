package co.ferrells.compositetrustmanager;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.util.Enumeration;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslManagerBundle;
import org.springframework.boot.ssl.SslStoreBundle;
import org.springframework.util.Assert;

/**
 * <b>INTERNAL</b> - Factory that composes a new Spring Boot {@link SslBundle} whose trust side is backed by a
 * {@link CompositeTrustManager}, a union of the JVM/system trust store and the trust material
 * from a caller-supplied source bundle.
 * <p>
 * Key material (private keys and the key store) from the source bundle is preserved without
 * modification; only the trust manager and trust store are replaced.
 * <p>
 * This class is not intended to be used directly outside of
 * {@link CompositeTrustManagerAutoConfiguration}.
 */
public final class CompositeTrustManagerSslBundle {

    public CompositeTrustManagerSslBundle() {}

    /**
     * Creates a composite {@link SslBundle} derived from {@code sourceBundle}.
     * <p>
     * The returned bundle:
     * <ul>
     *   <li>uses a {@link CompositeTrustManager} that trusts both the JVM/system CAs and the
     *       CAs from {@code sourceBundle}</li>
     *   <li>exposes a merged trust store containing all certificates from both sources</li>
     *   <li>preserves the key store, key password, options, and protocol from
     *       {@code sourceBundle} unchanged</li>
     * </ul>
     *
     * @param sourceBundle the existing Boot {@link SslBundle} to base the composite on; must not be null
     *
     * @return a new {@link SslBundle} backed by the composite trust manager
     */
    public static SslBundle create(SslBundle sourceBundle) {
        Assert.notNull(sourceBundle, "Source SslBundle must not be null");
        CompositeTrustManager compositeTrustManager = CompositeTrustManager.fromSystemAndBundle(sourceBundle);
        SslStoreBundle stores = mergeStores(sourceBundle);
        SslManagerBundle managers = createManagers(sourceBundle, compositeTrustManager);
        return SslBundle.of(stores, sourceBundle.getKey(), sourceBundle.getOptions(), sourceBundle.getProtocol(), managers);
    }

    /**
     * Builds a merged {@link SslStoreBundle} whose trust store contains every certificate from
     * both the JVM default trust store and the trust store in {@code sourceBundle}.
     * <p>
     * The JVM default trust store (loaded via
     * {@link CompositeTrustManager#loadDefaultTrustStore()}) is used as the base. Certificates
     * from the source bundle's trust store are copied into it, so the returned trust store is a
     * super-set of both. The key store from the source bundle is passed through unchanged.
     *
     * @param sourceBundle the source bundle whose trust store entries are merged in
     *
     * @return a new {@link SslStoreBundle} with the merged trust store
     */
    public static SslStoreBundle mergeStores(SslBundle sourceBundle) {
        KeyStore mergedTrustStore = CompositeTrustManager.loadDefaultTrustStore();
        KeyStore sourceTrustStore = sourceBundle.getStores().getTrustStore();
        if (sourceTrustStore != null) {
            copyCertificates(sourceTrustStore, mergedTrustStore);
        }
        
        return SslStoreBundle.of(sourceBundle.getStores().getKeyStore(),
                sourceBundle.getStores().getKeyStorePassword(),
                mergedTrustStore);
    }

    /**
     * Copies all certificate entries (not key or key-pair entries) from {@code source} into
     * {@code target}.
     * <p>
     * Alias conflicts between the two stores are resolved by {@link #uniqueAlias}. Entries
     * that are not certificate entries, or whose certificate is {@code null}, are silently
     * skipped.
     *
     * @param source the key store to copy certificates from
     * @param target the key store to copy certificates into
     *
     * @throws IllegalStateException if the copy fails due to a {@link KeyStoreException}
     */
    public static void copyCertificates(KeyStore source, KeyStore target) {
        try {
            Enumeration<String> aliases = source.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (!source.isCertificateEntry(alias)) {
                    continue;
                }
                
                Certificate certificate = source.getCertificate(alias);
                if (certificate == null) {
                    continue;
                }
                
                target.setCertificateEntry(uniqueAlias(target, alias), certificate);
            }
        }
        catch (KeyStoreException ex) {
            throw new IllegalStateException("Unable to merge the SSL bundle trust store into the system trust store", ex);
        }
    }

    /**
     * Returns an alias that does not already exist in {@code keyStore}.
     * <p>
     * If {@code alias} is not already in use it is returned as-is. Otherwise, a numeric
     * suffix is appended ({@code alias-1}, {@code alias-2}, …) until an unused name is found.
     *
     * @param keyStore the key store to check for alias collisions
     * @param alias    the preferred alias
     *
     * @return a collision-free alias derived from {@code alias}
     *
     * @throws KeyStoreException if {@code keyStore} has not been initialised
     */
    public static String uniqueAlias(KeyStore keyStore, String alias) throws KeyStoreException {
        if (!keyStore.containsAlias(alias)) {
            return alias;
        }
        
        int index = 1;
        while (keyStore.containsAlias(alias + "-" + index)) {
            index++;
        }
        
        return alias + "-" + index;
    }

    /**
     * Creates a {@link SslManagerBundle} that pairs the source bundle's key manager factory with
     * a {@link CompositeTrustManagerFactory} wrapping {@code compositeTrustManager}.
     * <p>
     * The key manager factory is taken directly from {@code sourceBundle} so that client
     * certificate authentication continues to use the original key material. The trust side is
     * replaced entirely with the composite trust manager.
     *
     * @param sourceBundle          the source bundle supplying the key manager factory
     * @param compositeTrustManager the composite trust manager to install on the trust side
     *
     * @return a {@link SslManagerBundle} backed by the composite trust manager
     */
    public static SslManagerBundle createManagers(SslBundle sourceBundle, X509TrustManager compositeTrustManager) {
        KeyManagerFactory keyManagerFactory = sourceBundle.getManagers().getKeyManagerFactory();
        
        return new SslManagerBundle() {
            @Override
            public KeyManagerFactory getKeyManagerFactory() {
                return keyManagerFactory;
            }

            @Override
            public CompositeTrustManagerFactory getTrustManagerFactory() {
                return new CompositeTrustManagerFactory(compositeTrustManager);
            }
        };
    }

}
