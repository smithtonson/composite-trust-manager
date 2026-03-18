package co.ferrells.CompositeTrustManager;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Provider;

import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.TrustManagerFactorySpi;

final class CompositeTrustManagerFactory extends TrustManagerFactory {

    private static final Provider PROVIDER = new Provider("CompositeTrustManagerProvider", 1.0,
            "Provides a fixed set of trust managers") {
        private static final long serialVersionUID = 1L;
    };

    CompositeTrustManagerFactory(TrustManager... trustManagers) {
        super(new FixedTrustManagerFactorySpi(trustManagers), PROVIDER, "fixed");
    }

    private static final class FixedTrustManagerFactorySpi extends TrustManagerFactorySpi {

        private final TrustManager[] trustManagers;

        private FixedTrustManagerFactorySpi(TrustManager[] trustManagers) {
            this.trustManagers = trustManagers.clone();
        }

        @Override
        protected void engineInit(KeyStore keyStore) throws KeyStoreException {
        }

        @Override
        protected void engineInit(ManagerFactoryParameters managerFactoryParameters)
                throws InvalidAlgorithmParameterException {
        }

        @Override
        protected TrustManager[] engineGetTrustManagers() {
            return this.trustManagers.clone();
        }

    }

}
