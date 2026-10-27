/*
 * Copyright 2019 Thunderberry.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nl.altindag.ssl.util;

import nl.altindag.desidero.OperatingSystem;
import nl.altindag.ssl.exception.GenericKeyStoreException;
import nl.altindag.sude.Logger;
import nl.altindag.sude.LoggerFactory;

import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.X509ExtendedTrustManager;
import java.security.KeyStore;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Creates a PKIX TrustManager using Windows root certificates as trust
 * anchors and intermediate CA certificates for certificate path building.
 *
 * @author Goldex60
 */
final class WindowsCATrustManagerFactory {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(WindowsCATrustManagerFactory.class);

    private WindowsCATrustManagerFactory() {
    }

    /**
     * Creates a PKIX TrustManager using Windows trusted roots and
     * intermediate CA certificates.
     *
     * @return the Windows CA PKIX TrustManager
     * @throws Exception if the TrustManager cannot be initialized
     */
    static X509ExtendedTrustManager create() throws Exception {
        if (OperatingSystem.get() != OperatingSystem.WINDOWS) {
            throw new UnsupportedOperationException("Windows CA is only available on Windows");
        }

        LOGGER.info("Initializing Windows CA TrustManager");

        Set<TrustAnchor> trustAnchors = loadWindowsTrustAnchors();
        if (trustAnchors.isEmpty()) {
            throw new IllegalStateException("No trusted root certificates found");
        }

        LOGGER.info(String.format("Loaded %d Windows trust anchors", trustAnchors.size()));

        List<X509Certificate> intermediates =
                OperatingSystem.WINDOWS.getIntermediateCertificates();

        LOGGER.info(String.format("Loaded %d Windows CA certificates", intermediates.size()));

        return create(trustAnchors, intermediates);
    }

    /**
     * Creates a PKIX TrustManager with separate trust anchors and
     * intermediate certificates.
     *
     * @param trustAnchors trusted root certificates
     * @param intermediates certificates used for path building
     * @return the configured PKIX TrustManager
     * @throws Exception if the TrustManager cannot be initialized
     */
    static X509ExtendedTrustManager create(
            Set<TrustAnchor> trustAnchors,
            List<X509Certificate> intermediates) throws Exception {

        PKIXBuilderParameters parameters =
                new PKIXBuilderParameters(trustAnchors, new X509CertSelector());

        CertStore intermediateStore = CertStore.getInstance(
                "Collection",
                new CollectionCertStoreParameters(intermediates));

        parameters.addCertStore(intermediateStore);

        X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManager(
                new CertPathTrustManagerParameters(parameters),
                "PKIX");

        LOGGER.info("Windows CA PKIX TrustManager initialized");

        return trustManager;
    }

    /**
     * Loads unique trusted root certificates from Windows ROOT stores.
     *
     * @return the trusted root certificates as trust anchors
     * @throws Exception if a Windows certificate store cannot be read
     */
    private static Set<TrustAnchor> loadWindowsTrustAnchors() throws Exception {
        Set<X509Certificate> rootCertificates = new HashSet<>();

        List<String> storeTypes = Arrays.asList(
                "Windows-ROOT",
                "Windows-ROOT-LOCALMACHINE",
                "Windows-ROOT-CURRENTUSER");

        for (String storeType : storeTypes) {
            LOGGER.debug(String.format("Loading Windows root store: %s", storeType));

            KeyStore store;
            try {
                store = KeyStoreUtils.createKeyStore(storeType, null);
            } catch (GenericKeyStoreException e) {
                LOGGER.debug(String.format("Windows store not available: %s", storeType));
                continue;
            }

            Enumeration<String> aliases = store.aliases();
            int count = 0;

            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();

                if (!store.isCertificateEntry(alias)) {
                    continue;
                }

                java.security.cert.Certificate certificate = store.getCertificate(alias);
                if (certificate instanceof X509Certificate
                        && rootCertificates.add((X509Certificate) certificate)) {
                    count++;
                }
            }

            LOGGER.info(String.format("Loaded %d certificates from %s", count, storeType));
        }

        Set<TrustAnchor> trustAnchors = new HashSet<>();
        for (X509Certificate certificate : rootCertificates) {
            trustAnchors.add(new TrustAnchor(certificate, null));
        }

        return trustAnchors;
    }
}
