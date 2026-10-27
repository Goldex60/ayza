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
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.X509ExtendedTrustManager;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mockStatic;

/**
 * Tests the Windows-specific PKIX TrustManager factory.
 *
 * @author Goldex60
 */
class WindowsCATrustManagerFactoryShould {

    private static final String CERTIFICATE_LOCATION = "certificates/windows-ca/";

    @Test
    void rejectCreationOnNonWindowsOperatingSystem() {
        try (MockedStatic<OperatingSystem> operatingSystem = mockStatic(OperatingSystem.class)) {
            operatingSystem.when(OperatingSystem::get).thenReturn(OperatingSystem.LINUX);

            assertThatThrownBy(WindowsCATrustManagerFactory::create)
                    .isInstanceOf(UnsupportedOperationException.class)
                    .hasMessage("Windows CA is only available on Windows");
        }
    }

    @Test
    void rejectServerCertificateWhenIntermediateCertificateIsMissing() throws Exception {

        // Load the root CA and server certificate.
        X509Certificate root = loadCertificate("root-ca.pem");
        X509Certificate server = loadCertificate("server.pem");

        // Trust only the root CA.
        TrustAnchor rootAnchor = new TrustAnchor(root, null);

        PKIXBuilderParameters parameters = new PKIXBuilderParameters(
                Collections.singleton(rootAnchor),
                new X509CertSelector());

        // The intermediate CA is deliberately not provided.
        // The server certificate alone cannot complete the certification path.
        parameters.setRevocationEnabled(false);

        CertPathTrustManagerParameters managerParameters =
                new CertPathTrustManagerParameters(parameters);

        X509ExtendedTrustManager trustManager =
                TrustManagerUtils.createTrustManager(managerParameters, "PKIX");

        // PKIX must reject the incomplete certification path.
        assertThatThrownBy(() -> trustManager.checkServerTrusted(
                new X509Certificate[]{server},
                "RSA"))
                .isInstanceOf(CertificateException.class);
    }

    @Test
    void rejectServerCertificateWhenRootCAIsNotTrusted() throws Exception {

        // Load the intermediate CA and server certificate.
        X509Certificate intermediate = loadCertificate("intermediate-ca.pem");
        X509Certificate server = loadCertificate("server.pem");

        // Use an unrelated certificate as the only trust anchor.
        // The legitimate root CA is deliberately not trusted.
        X509Certificate unrelated = (X509Certificate) CertificateUtils
                .loadCertificate("pem/self-signed.pem")
                .get(0);

        PKIXBuilderParameters parameters = new PKIXBuilderParameters(
                Collections.singleton(new TrustAnchor(unrelated, null)),
                new X509CertSelector());

        parameters.setRevocationEnabled(false);

        // The intermediate CA is available for path building,
        // but it must not become a trust anchor.
        CertStore intermediateStore = CertStore.getInstance(
                "Collection",
                new CollectionCertStoreParameters(
                        Collections.singletonList(intermediate)));

        parameters.addCertStore(intermediateStore);

        CertPathTrustManagerParameters managerParameters =
                new CertPathTrustManagerParameters(parameters);

        X509ExtendedTrustManager trustManager =
                TrustManagerUtils.createTrustManager(managerParameters, "PKIX");

        // The certification path must be rejected because its root is not trusted.
        assertThatThrownBy(() -> trustManager.checkServerTrusted(
                new X509Certificate[]{server},
                "RSA"))
                .isInstanceOf(CertificateException.class);
    }

    @Test
    void keepIntermediateCertificatesOutOfTrustAnchors() throws Exception {
        X509Certificate root = loadCertificate("root-ca.pem");
        X509Certificate intermediate = loadCertificate("intermediate-ca.pem");

        X509ExtendedTrustManager trustManager =
                WindowsCATrustManagerFactory.create(
                        Collections.singleton(new TrustAnchor(root, null)),
                        Collections.singletonList(intermediate));

        assertThat(trustManager.getAcceptedIssuers())
                .contains(root)
                .doesNotContain(intermediate);
    }

    @Test
    void buildCertificatePathUsingIntermediateCertificateFromCertStore() throws Exception {

        // Load the test certificate chain.
        X509Certificate root = loadCertificate("root-ca.pem");
        X509Certificate intermediate = loadCertificate("intermediate-ca.pem");
        X509Certificate server = loadCertificate("server.pem");

        // Trust only the root CA.
        TrustAnchor rootAnchor = new TrustAnchor(root, null);

        // Select the server certificate as the target of path building.
        X509CertSelector targetSelector = new X509CertSelector();
        targetSelector.setCertificate(server);

        PKIXBuilderParameters parameters = new PKIXBuilderParameters(
                Collections.singleton(rootAnchor),
                targetSelector);

        // Focus this test on constructing the certification path.
        parameters.setRevocationEnabled(false);

        // Provide the server and intermediate certificates as candidates.
        // The intermediate CA is not included in the trust anchors.
        CertStore certificateStore = CertStore.getInstance(
                "Collection",
                new CollectionCertStoreParameters(
                        Arrays.asList(server, intermediate)));

        parameters.addCertStore(certificateStore);

        // Build the path from the server certificate to the trusted root.
        CertPathBuilder builder = CertPathBuilder.getInstance("PKIX");
        CertPathBuilderResult result = builder.build(parameters);

        PKIXCertPathBuilderResult pkixResult =
                (PKIXCertPathBuilderResult) result;

        // The certification path contains the server and intermediate CA.
        // The trusted root is represented separately by the trust anchor.
        assertThat(pkixResult.getCertPath().getCertificates())
                .hasSize(2)
                .element(0).isEqualTo(server);

        assertThat(pkixResult.getCertPath().getCertificates().get(1))
                .isEqualTo(intermediate);

        assertThat(pkixResult.getTrustAnchor().getTrustedCert())
                .isEqualTo(root);
    }

    /**
     * Loads a single X.509 certificate from the Windows CA test resources.
     *
     * @param fileName the certificate file name
     * @return the loaded X.509 certificate
     */
    private static X509Certificate loadCertificate(String fileName) {
        return (X509Certificate) CertificateUtils
                .loadCertificate(CERTIFICATE_LOCATION + fileName)
                .get(0);
    }
}
