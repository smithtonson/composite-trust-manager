package co.ferrells.CompositeTrustManager;

import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.net.ssl.X509TrustManager;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

class CompositeTrustManagerTests {

    @Test
    void acceptsCertificateChainWhenAnyDelegateTrustsIt() throws Exception {
        X509Certificate certificate = mock(X509Certificate.class);
        CompositeTrustManager trustManager = new CompositeTrustManager(List.of(
                rejectingTrustManager(),
                trustingTrustManager(certificate)));

        trustManager.checkServerTrusted(new X509Certificate[] { certificate }, "RSA");

        assertThat(trustManager.getAcceptedIssuers()).containsExactly(certificate);
    }

    @Test
    void rejectsCertificateChainWhenAllDelegatesRejectIt() {
        X509Certificate certificate = mock(X509Certificate.class);
        CompositeTrustManager trustManager = new CompositeTrustManager(List.of(
                rejectingTrustManager(),
                rejectingTrustManager()));

        assertThatThrownBy(() -> trustManager.checkServerTrusted(new X509Certificate[] { certificate }, "RSA"))
                .isInstanceOf(CertificateException.class)
                .hasMessageContaining("No configured TrustManagers trust this server certificate chain");
    }

    @Test
    void loadDefaultTrustStoreSucceedsWhenTrustStorePropertyIsNone() {
        String previous = System.getProperty("javax.net.ssl.trustStore");
        try {
            System.setProperty("javax.net.ssl.trustStore", "NONE");
            assertThatCode(() -> {
                KeyStore trustStore = CompositeTrustManager.loadDefaultTrustStore();
                assertThat(trustStore).isNotNull();
                assertThat(trustStore.size()).isZero();
            }).doesNotThrowAnyException();
        }
        finally {
            if (previous != null) {
                System.setProperty("javax.net.ssl.trustStore", previous);
            }
            else {
                System.clearProperty("javax.net.ssl.trustStore");
            }
        }
    }

    private static X509TrustManager rejectingTrustManager() {
        return new StubX509TrustManager(List.of(), false);
    }

    private static X509TrustManager trustingTrustManager(X509Certificate certificate) {
        return new StubX509TrustManager(List.of(certificate), true);
    }

    private record StubX509TrustManager(List<X509Certificate> acceptedIssuers, boolean trust) implements X509TrustManager {

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            if (!this.trust) {
                throw new CertificateException("Rejected");
            }
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            if (!this.trust) {
                throw new CertificateException("Rejected");
            }
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return this.acceptedIssuers.toArray(X509Certificate[]::new);
        }
    }
}
