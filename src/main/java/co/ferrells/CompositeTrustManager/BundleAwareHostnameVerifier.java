package co.ferrells.CompositeTrustManager;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;

/**
 * A {@link HostnameVerifier} that enforces strict hostname verification for certificates
 * trusted by the JVM system trust store, while relaxing hostname verification for
 * certificates that are only trusted by the configured Spring Boot SSL bundle.
 * <p>
 * This is useful for private or embedded devices (NAS devices, routers, etc.) that
 * use self-signed certificates with no Subject Alternative Names (SANs). Hostname
 * verification would normally fail for such devices, but since they are explicitly
 * trusted via the SSL bundle, it is safe to relax the check for them specifically.
 * <p>
 * Certificate <em>trust</em> validation (chain verification, expiry, revocation) is
 * always enforced for all certificates regardless of this verifier - relaxing hostname
 * verification does not bypass trust validation.
 * <p>
 * The check works as follows:
 * <ol>
 *   <li>Obtain the peer certificate chain from the {@link SSLSession}</li>
 *   <li>Attempt to validate the chain against the system-only trust managers</li>
 *   <li>If system validation succeeds → the cert is publicly trusted → enforce strict
 *       hostname verification using the JVM default verifier</li>
 *   <li>If system validation fails → the cert is only trusted via the SSL bundle →
 *       skip hostname verification (allow the connection)</li>
 * </ol>
 */
public class BundleAwareHostnameVerifier implements HostnameVerifier {

    private final List<X509TrustManager> systemTrustManagers;
    private final HostnameVerifier strictVerifier;

    /**
     * Creates a verifier using the provided system trust managers for the
     * bundle vs system check and the provided strict verifier for public
     * CA certificates.
     *
     * @param systemTrustManagers trust managers loaded from the JVM default trust store only
     * @param strictVerifier      verifier to delegate to for system-trusted certificates
     */
    public BundleAwareHostnameVerifier(List<X509TrustManager> systemTrustManagers,
            HostnameVerifier strictVerifier) {
        this.systemTrustManagers = List.copyOf(systemTrustManagers);
        this.strictVerifier = strictVerifier;
    }

    @Override
    public boolean verify(String hostname, SSLSession session) {
        X509Certificate[] chain = getPeerCertificates(session);

        // No peer certificates, defer to strict verifier (will likely reject)
        if (chain == null || chain.length == 0) {
            return this.strictVerifier.verify(hostname, session);
        }

        // Publicly trusted certificate, enforce strict hostname verification
        if (isTrustedBySystem(chain)) {
            return this.strictVerifier.verify(hostname, session);
        }

        // Certificate is only trusted via the SSL bundle (not by system CAs)
        // skip hostname verification. Trust validation was already enforced by the
        // composite X509TrustManager during the TLS handshake.
        return true;
    }

    private boolean isTrustedBySystem(X509Certificate[] chain) {
        String authType = chain[0].getPublicKey().getAlgorithm();
        
        for (X509TrustManager trustManager : this.systemTrustManagers) {
            try {
                trustManager.checkServerTrusted(chain, authType);
                return true;
            }
            catch (CertificateException | RuntimeException ex) {
                // This delegate does not trust the chain, try the next one
            }
        }
        
        return false;
    }

    private static X509Certificate[] getPeerCertificates(SSLSession session) {
        try {
            return (X509Certificate[]) session.getPeerCertificates();
        }
        catch (SSLPeerUnverifiedException ex) {
            return null;
        }
    }

}
