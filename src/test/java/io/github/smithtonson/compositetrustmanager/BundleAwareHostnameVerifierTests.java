package io.github.smithtonson.compositetrustmanager;

import io.github.smithtonson.compositetrustmanager.BundleAwareHostnameVerifier;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link BundleAwareHostnameVerifier}.
 */
class BundleAwareHostnameVerifierTests {

    private final X509TrustManager systemTrustManager = mock(X509TrustManager.class);
    private final HostnameVerifier strictVerifier = mock(HostnameVerifier.class);
    private final BundleAwareHostnameVerifier verifier = new BundleAwareHostnameVerifier(
            List.of(systemTrustManager), strictVerifier);

    @Test
    void delegatesToStrictVerifierForSystemTrustedCertificate() throws Exception {
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getPublicKey()).thenReturn(mock(java.security.PublicKey.class));
        when(cert.getPublicKey().getAlgorithm()).thenReturn("RSA");
        SSLSession session = mockSession(cert);

        // System trust manager accepts the cert
        // (no exception thrown from checkServerTrusted)

        when(strictVerifier.verify("myhost", session)).thenReturn(true);

        boolean result = verifier.verify("myhost", session);

        assertThat(result).isTrue();
        verify(strictVerifier).verify("myhost", session);
    }

    @Test
    void allowsConnectionWithoutStrictCheckForBundleOnlyCertificate() throws Exception {
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getPublicKey()).thenReturn(mock(java.security.PublicKey.class));
        when(cert.getPublicKey().getAlgorithm()).thenReturn("RSA");
        SSLSession session = mockSession(cert);

        // System trust manager rejects the cert
        org.mockito.Mockito.doThrow(new CertificateException("not trusted by system"))
                .when(systemTrustManager).checkServerTrusted(any(), anyString());

        boolean result = verifier.verify("wronghost.example.com", session);

        // Bundle-only cert: should allow without delegating to strict verifier
        assertThat(result).isTrue();
        verify(strictVerifier, never()).verify(anyString(), any());
    }

    @Test
    void delegatesToStrictVerifierWhenNoPeerCertificatesAvailable() throws Exception {
        SSLSession session = mock(SSLSession.class);
        when(session.getPeerCertificates()).thenThrow(new SSLPeerUnverifiedException("no certs"));

        when(strictVerifier.verify("myhost", session)).thenReturn(false);

        boolean result = verifier.verify("myhost", session);

        assertThat(result).isFalse();
        verify(strictVerifier).verify("myhost", session);
    }

    @Test
    void delegatesToStrictVerifierWhenCertChainIsEmpty() throws Exception {
        SSLSession session = mockSession();

        when(strictVerifier.verify("myhost", session)).thenReturn(false);

        boolean result = verifier.verify("myhost", session);

        assertThat(result).isFalse();
        verify(strictVerifier).verify("myhost", session);
    }

    @Test
    void handlesRuntimeExceptionFromSystemTrustManagerAsBundleOnlyCert() throws Exception {
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getPublicKey()).thenReturn(mock(java.security.PublicKey.class));
        when(cert.getPublicKey().getAlgorithm()).thenReturn("RSA");
        SSLSession session = mockSession(cert);

        org.mockito.Mockito.doThrow(new RuntimeException("unexpected"))
                .when(systemTrustManager).checkServerTrusted(any(), anyString());

        boolean result = verifier.verify("myhost", session);

        // RuntimeException from system trust manager is treated as "not system trusted"
        assertThat(result).isTrue();
        verify(strictVerifier, never()).verify(anyString(), any());
    }

    private static SSLSession mockSession(X509Certificate... certs) throws Exception {
        SSLSession session = mock(SSLSession.class);
        when(session.getPeerCertificates()).thenReturn(certs);
        return session;
    }

}
