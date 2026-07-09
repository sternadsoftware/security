/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.auth.ldap.srv;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Collection;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.ssl.KeyStoreKeyManager;
import com.unboundid.util.ssl.SSLUtil;

/**
 * Standalone local LDAPS stand-in for manual FIPS/mTLS testing — see {@code LDAP_FIPS_LOCAL_MTLS_GUIDE.md}.
 *
 * <p>Reuses the repo's demo PKI: the {@code node-0} server cert (SAN includes {@code localhost}), the
 * {@code truststore} (Example Com Root CA), and the {@code spock} client cert — all chaining to one
 * root. It speaks real LDAP, so a bind against the loaded LDIF actually succeeds, and (with
 * {@code need.client.auth=true}) it <b>requires and verifies</b> a client cert — proving happy-path
 * authentication + mTLS in one small process. No role distribution.
 *
 * <p>Run: {@code ./gradlew ldapMtlsServer} (or any launcher with the test runtime classpath). All
 * inputs have defaults resolved from {@code src/test/resources/ldap/} relative to the project dir and
 * are overridable with {@code -Dkey=value}.
 */
public final class LocalLdapMtlsServer {

    private LocalLdapMtlsServer() {}

    public static void main(String[] args) throws Exception {
        final int port = Integer.getInteger("ldaps.port", 8636);
        final String keystore = System.getProperty("server.keystore", "src/test/resources/ldap/node-0-keystore.jks");
        final String keystorePw = System.getProperty("server.keystore.password", "changeit");
        final String truststore = System.getProperty("truststore", "src/test/resources/ldap/truststore.jks");
        final String truststorePw = System.getProperty("truststore.password", "changeit");
        final String ldif = System.getProperty("ldif", "src/test/resources/ldap/local-mtls.ldif");
        final boolean needClientAuth = Boolean.parseBoolean(System.getProperty("need.client.auth", "true"));

        // Trust managers from the JKS truststore (Example Com Root CA) — used to verify client certs.
        final KeyStore ts = KeyStore.getInstance("JKS");
        try (InputStream in = new FileInputStream(truststore)) {
            ts.load(in, truststorePw.toCharArray());
        }
        final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ts);

        final SSLUtil serverSSLUtil = new SSLUtil(new KeyStoreKeyManager(keystore, keystorePw.toCharArray()), tmf.getTrustManagers()[0]);

        SSLServerSocketFactory ssf = serverSSLUtil.createSSLServerSocketFactory();
        if (needClientAuth) {
            ssf = new NeedClientAuthSSLServerSocketFactory(ssf);
        }

        final InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(new DN("o=TEST"));
        config.setSchema(Schema.getDefaultStandardSchema());
        config.setEnforceAttributeSyntaxCompliance(false);
        config.setEnforceSingleStructuralObjectClass(false);
        final Collection<InMemoryListenerConfig> listeners = new ArrayList<>();
        listeners.add(InMemoryListenerConfig.createLDAPSConfig("ldaps", port, ssf));
        config.setListenerConfigs(listeners);

        final InMemoryDirectoryServer server = new InMemoryDirectoryServer(config);
        server.importFromLDIF(true, ldif);
        server.startListening();

        System.out.println(
            "Local LDAPS mTLS stand-in listening on localhost:"
                + port
                + "  (client cert "
                + (needClientAuth ? "REQUIRED" : "optional")
                + ", base o=TEST, LDIF="
                + ldif
                + ")"
        );
        System.out.println("Press Ctrl-C to stop.");
        Thread.currentThread().join();
    }

    /** Wraps an {@link SSLServerSocketFactory} so every accepted socket demands + verifies a client cert (mTLS). */
    private static final class NeedClientAuthSSLServerSocketFactory extends SSLServerSocketFactory {

        private final SSLServerSocketFactory delegate;

        NeedClientAuthSSLServerSocketFactory(SSLServerSocketFactory delegate) {
            this.delegate = delegate;
        }

        private ServerSocket require(ServerSocket socket) {
            ((SSLServerSocket) socket).setNeedClientAuth(true);
            return socket;
        }

        @Override
        public ServerSocket createServerSocket() throws IOException {
            return require(delegate.createServerSocket());
        }

        @Override
        public ServerSocket createServerSocket(int port) throws IOException {
            return require(delegate.createServerSocket(port));
        }

        @Override
        public ServerSocket createServerSocket(int port, int backlog) throws IOException {
            return require(delegate.createServerSocket(port, backlog));
        }

        @Override
        public ServerSocket createServerSocket(int port, int backlog, InetAddress ifAddress) throws IOException {
            return require(delegate.createServerSocket(port, backlog, ifAddress));
        }

        @Override
        public String[] getDefaultCipherSuites() {
            return delegate.getDefaultCipherSuites();
        }

        @Override
        public String[] getSupportedCipherSuites() {
            return delegate.getSupportedCipherSuites();
        }
    }
}
