package co.ferrells.CompositeTrustManager;

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

final class CompositeTrustManagerSslBundle {

    private CompositeTrustManagerSslBundle() {
    }

    static SslBundle create(SslBundle sourceBundle) {
        Assert.notNull(sourceBundle, "Source SslBundle must not be null");
        CompositeTrustManager compositeTrustManager = CompositeTrustManager.fromSystemAndBundle(sourceBundle);
        SslStoreBundle stores = mergeStores(sourceBundle);
        SslManagerBundle managers = createManagers(sourceBundle, compositeTrustManager);
        return SslBundle.of(stores, sourceBundle.getKey(), sourceBundle.getOptions(), sourceBundle.getProtocol(), managers);
    }

    private static SslStoreBundle mergeStores(SslBundle sourceBundle) {
        KeyStore mergedTrustStore = CompositeTrustManager.loadDefaultTrustStore();
        KeyStore sourceTrustStore = sourceBundle.getStores().getTrustStore();
        if (sourceTrustStore != null) {
            copyCertificates(sourceTrustStore, mergedTrustStore);
        }
        return SslStoreBundle.of(sourceBundle.getStores().getKeyStore(), sourceBundle.getStores().getKeyStorePassword(),
                mergedTrustStore);
    }

    private static void copyCertificates(KeyStore source, KeyStore target) {
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

    private static String uniqueAlias(KeyStore keyStore, String alias) throws KeyStoreException {
        if (!keyStore.containsAlias(alias)) {
            return alias;
        }
        int index = 1;
        while (keyStore.containsAlias(alias + "-" + index)) {
            index++;
        }
        return alias + "-" + index;
    }

    private static SslManagerBundle createManagers(SslBundle sourceBundle, X509TrustManager compositeTrustManager) {
        KeyManagerFactory keyManagerFactory = sourceBundle.getManagers().getKeyManagerFactory();
        return new SslManagerBundle() {
            @Override
            public KeyManagerFactory getKeyManagerFactory() {
                return keyManagerFactory;
            }

            @Override
            public FixedTrustManagerFactory getTrustManagerFactory() {
                return new FixedTrustManagerFactory(compositeTrustManager);
            }
        };
    }
}
