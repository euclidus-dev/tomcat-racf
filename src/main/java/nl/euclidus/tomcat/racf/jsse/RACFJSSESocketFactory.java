/*
    Copyright 2016 Gerard Borst and Harry Metske
    
    This file is part of tomcat-racf.

    tomcat-racf is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    tomcat-racf is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with tomcat-racf.  If not, see <http://www.gnu.org/licenses/>.
    
*/
package nl.euclidus.tomcat.racf.jsse;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertPathParameters;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.X509CertSelector;
import java.security.InvalidParameterException;

import java.util.Collection;
import java.util.Locale;
import java.util.Vector;

import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;

import nl.euclidus.tomcat.racf.RTABuildInfo;

import static nl.euclidus.tomcat.racf.RTAConstants.*;

import org.apache.tomcat.util.net.AbstractEndpoint;
import org.apache.tomcat.util.net.Constants;
import org.apache.tomcat.util.net.SSLUtil;
import org.apache.tomcat.util.net.ServerSocketFactory;
import org.apache.tomcat.util.net.jsse.JSSEKeyManager;
import org.apache.tomcat.util.res.StringManager;


/**
 * RACF SSL server socket factory. It <b>requires</b> a valid RSA key in RACF 
 * <br/>
 * 
 * 
 * @author Gerard Borst
 */
public class RACFJSSESocketFactory implements ServerSocketFactory, SSLUtil {

    private static final StringManager sm =
        StringManager.getManager("nl.euclidus.tomcat.racf.res");
    
    static final org.apache.juli.logging.Log log =
        org.apache.juli.logging.LogFactory.getLog(RACFJSSESocketFactory.class);

    private AbstractEndpoint endpoint;

    protected boolean initialized;
    protected SSLServerSocketFactory sslProxy = null;
    protected String[] enabledCiphers;
    protected boolean allowUnsafeLegacyRenegotiation = false;
    
    // Defaults - made public where re-used
    private static final String defaultProtocol = "TLS";
    private static final String defaultKeystoreType = RACF_SSL_DEFAULT_KEYSTORE_TYPE;
    private static final int defaultSessionCacheSize = 0;
    private static final int defaultSessionTimeout = 86400;
    /**
     * Flag to state that we require client authentication.
     */
    protected boolean requireClientAuth = false;

    /**
     * Flag to state that we would like client authentication.
     */
    protected boolean wantClientAuth    = false;


    public RACFJSSESocketFactory (AbstractEndpoint endpoint) {
        this.endpoint = endpoint;
    }

    @Override
    public ServerSocket createSocket (int port)
        throws IOException
    {
        if (!initialized) init();
        ServerSocket socket = sslProxy.createServerSocket(port);
        initServerSocket(socket);
        return socket;
    }
    
    @Override
    public ServerSocket createSocket (int port, int backlog)
        throws IOException
    {
        if (!initialized) init();
        ServerSocket socket = sslProxy.createServerSocket(port, backlog);
        initServerSocket(socket);
        return socket;
    }
    
    @Override
    public ServerSocket createSocket (int port, int backlog,
                                      InetAddress ifAddress)
        throws IOException
    {   
        if (!initialized) init();
        ServerSocket socket = sslProxy.createServerSocket(port, backlog,
                                                          ifAddress);
        initServerSocket(socket);
        return socket;
    }
    
    @Override
    public Socket acceptSocket(ServerSocket socket)
        throws IOException
    {
        SSLSocket asock = null;
        try {
             asock = (SSLSocket)socket.accept();
        } catch (SSLException e){
          throw new SocketException("SSL handshake error" + e.toString());
        }
        return asock;
    }
    
    @Override
    public void handshake(Socket sock) throws IOException {
        // We do getSession instead of startHandshake() so we can call this multiple times
        SSLSession session = ((SSLSocket)sock).getSession();
        if (session.getCipherSuite().equals("SSL_NULL_WITH_NULL_NULL"))
            throw new IOException("SSL handshake failed. Ciper suite in SSL Session is SSL_NULL_WITH_NULL_NULL");

        if (!allowUnsafeLegacyRenegotiation) {
            // Prevent futher handshakes by removing all cipher suites
            ((SSLSocket) sock).setEnabledCipherSuites(new String[0]);
        }
    }

    /*
     * Determines the SSL cipher suites to be enabled.
     *
     * @param requestedCiphers Comma-separated list of requested ciphers
     * @param supportedCiphers Array of supported ciphers
     *
     * @return Array of SSL cipher suites to be enabled, or null if none of the
     * requested ciphers are supported
     */
    protected String[] getEnabledCiphers(String requestedCiphers,
                                         String[] supportedCiphers) {

        String[] result = null;

        if (SSL_ALLOW_ALL_SUPPORTED_CIPHERS.equals(requestedCiphers)) {
            return supportedCiphers;
        }

        if (requestedCiphers != null) {
            Vector<String> vec = null;
            String cipher = requestedCiphers;
            int index = requestedCiphers.indexOf(',');
            if (index != -1) {
                int fromIndex = 0;
                while (index != -1) {
                    cipher =
                        requestedCiphers.substring(fromIndex, index).trim();
                    if (cipher.length() > 0) {
                        /*
                         * Check to see if the requested cipher is among the
                         * supported ciphers, i.e., may be enabled
                         */
                        for (int i=0; supportedCiphers != null
                                     && i<supportedCiphers.length; i++) {
                            if (supportedCiphers[i].equals(cipher)) {
                                if (vec == null) {
                                    vec = new Vector<String>();
                                }
                                vec.addElement(cipher);
                                break;
                            }
                        }
                    }
                    fromIndex = index+1;
                    index = requestedCiphers.indexOf(',', fromIndex);
                } // while
                cipher = requestedCiphers.substring(fromIndex);
            }

            if (cipher != null) {
                cipher = cipher.trim();
                if (cipher.length() > 0) {
                    /*
                     * Check to see if the requested cipher is among the
                     * supported ciphers, i.e., may be enabled
                     */
                    for (int i=0; supportedCiphers != null
                                 && i<supportedCiphers.length; i++) {
                        if (supportedCiphers[i].equals(cipher)) {
                            if (vec == null) {
                                vec = new Vector<String>();
                            }
                            vec.addElement(cipher);
                            break;
                        }
                    }
                }
            }           

            if (vec != null) {
                result = new String[vec.size()];
                vec.copyInto(result);
            }
        } else {
            result = sslProxy.getDefaultCipherSuites();
        }

        return result;
    }
     
    /*
     * Gets the SSL server's keystore password.
     */
    protected String getKeystorePassword() {
        return SSL_KEY_PASSWORD;
    }

    /*
     * Gets the SSL server's keystore.
     */
    protected KeyStore getKeystore(String type, String provider, String pass)
            throws IOException {
    	String keyRing = endpoint.getProperty(RACF_SSL_ATTR_KEYRING);
        
        if (keyRing == null)
            keyRing = RACF_SSL_KEYRING_DEFAULT_VALUE;
    	return getStore(type, provider, keyRing);
    }

    /*
     * Gets the SSL server's truststore.
     */
    protected KeyStore getTrustStore(String keystoreType,
            String keystoreProvider) throws IOException {
    	String keyRing = endpoint.getProperty(RACF_SSL_ATTR_KEYRING);
        
        if (keyRing == null)
            keyRing = RACF_SSL_KEYRING_DEFAULT_VALUE;
    	return getStore(keystoreType, keystoreProvider, keyRing);
    }

	/**
	 * getStore most important change compared to JSSEImplementation.
	 * 
	 * @param type
	 * @param provider
	 * @param path
	 * @param pass
	 * @return
	 * @throws IOException
	 */
	private KeyStore getStore(String type, String provider, String keyRing) throws IOException {
		String keyStoreType = type.toUpperCase();
		KeyStore ks = null;
		log.debug("SSL Type: " + keyStoreType + " Provider: " + provider + " Keyring: " + keyRing);
		InputStream istream = null;
		try {
			if (!SUPPORTED_KEYSTORES.contains(keyStoreType)) {
				
				if ("JKS".equals(keyStoreType)) {
					//Default type
					keyStoreType = defaultKeystoreType;	
					log.debug("Default Keystore Type set: " + keyStoreType );
				} else {
					log.error(sm.getString("jsse.invalid_ssl_conf", 
							"Keystore type " + keyStoreType + "not supported"));
					throw new InvalidParameterException(sm.getString("jsse.invalid_ssl_conf", 
							"Keystore type " + keyStoreType + "not supported"));
				}
			}				
			
			ks = KeyStore.getInstance(keyStoreType, RACF_SSL_KEYSTORE_PROVIDER);			
			
			istream = SUPPORTED_KEYSTORES.getRacfInputStream(SUPPORTED_KEYSTORES.valueOf(keyStoreType), keyRing);

			ks.load(istream, null);
		} catch (IOException ioe) {
			log.error(sm.getString("jsse.keystore_load_failed", keyStoreType, keyRing, ioe.getMessage()), ioe);
			throw ioe;
		} catch (Exception ex) {
			String msg = sm.getString("jsse.keystore_load_failed", keyStoreType, keyRing, ex.getMessage());
			log.error(msg, ex);
			throw new IOException(msg);
		} finally {
			if (istream != null) {
				try {
					istream.close();
				} catch (IOException ioe) {
					// Do nothing
				}
			}
		}

		return ks;
	}

    /**
     * Reads the keystore and initializes the SSL socket factory.
     * @throws IOException 
     */
    void init() throws IOException {
        try {

            String clientAuthStr = endpoint.getClientAuth();
            if("true".equalsIgnoreCase(clientAuthStr) ||
               "yes".equalsIgnoreCase(clientAuthStr)) {
                requireClientAuth = true;
            } else if("want".equalsIgnoreCase(clientAuthStr)) {
                wantClientAuth = true;
            }

            // SSL protocol variant (e.g., TLS, SSL v3, etc.)
            String protocol = endpoint.getSslProtocol();
            if (protocol == null) {
                protocol = SSL_DEFAULT_PROTOCOL;
            }

            // Certificate encoding algorithm (e.g., SunX509)
            String algorithm = endpoint.getAlgorithm();
            if (algorithm == null) {
                algorithm = KeyManagerFactory.getDefaultAlgorithm();
            }

            String keystoreType = endpoint.getKeystoreType();

            String trustAlgorithm = endpoint.getTruststoreAlgorithm();
            if( trustAlgorithm == null ) {
                trustAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
            }
            
            String keyLabel = endpoint.getProperty(RACF_SSL_ATTR_KEY_LABEL);
            log.debug("Keylabel: " + keyLabel);

            // Create and init SSLContext
            SSLContext context = SSLContext.getInstance(protocol); 
            context.init(getKeyManagers(keystoreType, RACF_SSL_KEYSTORE_PROVIDER,
                    algorithm,
                    keyLabel),
                    getTrustManagers(keystoreType, RACF_SSL_KEYSTORE_PROVIDER,
                            trustAlgorithm),
                    new SecureRandom());

            // Configure SSL session cache
            int sessionCacheSize;
            if (endpoint.getSessionCacheSize() != null) {
                sessionCacheSize = Integer.parseInt(
                        endpoint.getSessionCacheSize());
            } else {
                sessionCacheSize = SSL_DEFAULT_SESSION_CACHESIZE;
            }
            int sessionTimeout;
            if (endpoint.getSessionTimeout() != null) {
                sessionTimeout = Integer.parseInt(endpoint.getSessionTimeout());
            } else {
                sessionTimeout = SSL_DEFAULT_SESSION_TIMEOUT;
            }
            SSLSessionContext sessionContext =
                context.getServerSessionContext();
            if (sessionContext != null) {
                sessionContext.setSessionCacheSize(sessionCacheSize);
                sessionContext.setSessionTimeout(sessionTimeout);
            }

            // create proxy
            sslProxy = context.getServerSocketFactory();

            // Determine which cipher suites to enable
            String requestedCiphers = endpoint.getCiphers();
            enabledCiphers = getEnabledCiphers(requestedCiphers,
                    sslProxy.getSupportedCipherSuites());
            
            if (log.isDebugEnabled()) {
            	StringBuffer enabledCiphs = new StringBuffer();
            	for (String s : enabledCiphers) {
            		enabledCiphs.append(s);
            		enabledCiphs.append(" ");
            	}
            	log.debug("Requested Ciphers: " + requestedCiphers);
            	log.debug("Enabled Ciphers: " + enabledCiphs);
            }

            allowUnsafeLegacyRenegotiation = "true".equals(
                    endpoint.getAllowUnsafeLegacyRenegotiation());
            
            // Check the SSL config is OK
            checkConfig();
        } catch(Exception e) {
            if( e instanceof IOException )
                throw (IOException)e;
            throw new IOException(e.getMessage());
        }
        // Display build info on console
		log.info(sm.getString("logging.info.build_date", RacfBuildInfo.getBuildDate()));
		log.info(sm.getString("logging.info.build_release",	RacfBuildInfo.getBuildRelease()));
		log.info(sm.getString("logging.info.status", RACFJSSEImplementation.class.getName()));
    }

    /**
     * Gets the initialized key managers.
     */
    protected KeyManager[] getKeyManagers(String keystoreType,
                                          String keystoreProvider,
                                          String algorithm,
                                          String keyLabel)
                throws Exception {

        KeyManager[] kms = null;

        String keystorePass = getKeystorePassword();

        KeyStore ks = getKeystore(keystoreType, keystoreProvider, keystorePass);
        if (keyLabel != null && !ks.isKeyEntry(keyLabel)) {
            throw new IOException(
                    sm.getString("jsse.alias_no_key_entry", keyLabel));
        }

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(algorithm);
        kmf.init(ks, keystorePass.toCharArray());

        kms = kmf.getKeyManagers();
        if (keyLabel != null) {
            String label = keyLabel;
            if (RACF_SSL_DEFAULT_KEYSTORE_TYPE.equals(keystoreType)) {
                label = label.toLowerCase(Locale.ENGLISH);
            }
            for(int i=0; i<kms.length; i++) {
                kms[i] = new JSSEKeyManager((X509KeyManager)kms[i], label);
            }
        }

        return kms;
    }

    /**
     * Gets the initialized trust managers.
     */
    protected TrustManager[] getTrustManagers(String keystoreType,
            String keystoreProvider, String algorithm)
        throws Exception {
        String crlf = endpoint.getCrlFile();
        
        TrustManager[] tms = null;
        
        KeyStore trustStore = getTrustStore(keystoreType, keystoreProvider);
        if (trustStore != null) {
            if (crlf == null) {
                TrustManagerFactory tmf =
                    TrustManagerFactory.getInstance(algorithm);
                tmf.init(trustStore);
                tms = tmf.getTrustManagers();
            } else {
                TrustManagerFactory tmf =
                    TrustManagerFactory.getInstance(algorithm);
                CertPathParameters params =
                    getParameters(algorithm, crlf, trustStore);
                ManagerFactoryParameters mfp =
                    new CertPathTrustManagerParameters(params);
                tmf.init(mfp);
                tms = tmf.getTrustManagers();
            }
        }
        
        return tms;
    }
    
    /**
     * Return the initialization parameters for the TrustManager.
     * Currently, only the default <code>PKIX</code> is supported.
     * 
     * @param algorithm The algorithm to get parameters for.
     * @param crlf The path to the CRL file.
     * @param trustStore The configured TrustStore.
     * @return The parameters including the CRLs and TrustStore.
     */
    protected CertPathParameters getParameters(String algorithm, 
                                                String crlf, 
                                                KeyStore trustStore)
        throws Exception {
        CertPathParameters params = null;
        if("PKIX".equalsIgnoreCase(algorithm)) {
            PKIXBuilderParameters xparams =
                new PKIXBuilderParameters(trustStore, new X509CertSelector());
            Collection<? extends CRL> crls = getCRLs(crlf);
            CertStoreParameters csp = new CollectionCertStoreParameters(crls);
            CertStore store = CertStore.getInstance("Collection", csp);
            xparams.addCertStore(store);
            xparams.setRevocationEnabled(true);
            String trustLength = endpoint.getTrustMaxCertLength();
            if(trustLength != null) {
                try {
                    xparams.setMaxPathLength(Integer.parseInt(trustLength));
                } catch(Exception ex) {
                    log.warn("Bad maxCertLength: "+trustLength);
                }
            }

            params = xparams;
        } else {
            throw new CRLException("CRLs not supported for type: "+algorithm);
        }
        return params;
    }


    /**
     * Load the collection of CRLs.
     * 
     */
    protected Collection<? extends CRL> getCRLs(String crlf) 
        throws IOException, CRLException, CertificateException {

        File crlFile = new File(crlf);
        if( !crlFile.isAbsolute() ) {
            crlFile = new File(
                    System.getProperty(Constants.CATALINA_BASE_PROP), crlf);
        }
        Collection<? extends CRL> crls = null;
        InputStream is = null;
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            is = new FileInputStream(crlFile);
            crls = cf.generateCRLs(is);
        } catch(IOException iex) {
            throw iex;
        } catch(CRLException crle) {
            throw crle;
        } catch(CertificateException ce) {
            throw ce;
        } finally { 
            if(is != null) {
                try{
                    is.close();
                } catch(Exception ex) {
                    // Ignore
                }
            }
        }
        return crls;
    }

    /**
     * Set the SSL protocol variants to be enabled.
     * @param socket the SSLServerSocket.
     * @param protocols the protocols to use.
     */
    protected void setEnabledProtocols(SSLServerSocket socket,
            String []protocols){
        if (protocols != null) {
            socket.setEnabledProtocols(protocols);
        }
    }

    /**
     * Determines the SSL protocol variants to be enabled.
     *
     * @param socket The socket to get supported list from.
     * @param requestedProtocols Array of requested protocol names all of which
     *                           must be non-null and non-zero length
     *
     * @return Array of SSL protocol variants to be enabled, or null if none of
     * the requested protocol variants are supported
     */
    protected String[] getEnabledProtocols(SSLServerSocket socket,
                                           String[] requestedProtocols){
        String[] supportedProtocols = socket.getSupportedProtocols();

        String[] enabledProtocols = null;

        if (requestedProtocols != null && requestedProtocols.length > 0) {
            Vector<String> vec = null;
            for (String protocol : requestedProtocols) {
                /*
                 * Check to see if the requested protocol is among the supported
                 * protocols, i.e., may be enabled
                 */
                for (int i=0; supportedProtocols != null &&
                        i < supportedProtocols.length; i++) {
                    if (supportedProtocols[i].equals(protocol)) {
                        if (vec == null) {
                            vec = new Vector<String>();
                        }
                        vec.addElement(protocol);
                        break;
                    }
                }
            }

            if (vec != null) {
                enabledProtocols = new String[vec.size()];
                vec.copyInto(enabledProtocols);
            }
        }

        return enabledProtocols;
    }

    /**
     * Configure Client authentication for this version of JSSE.  The
     * JSSE included in Java 1.4 supports the 'want' value.  Prior
     * versions of JSSE will treat 'want' as 'false'.
     * @param socket the SSLServerSocket
     */
    protected void configureClientAuth(SSLServerSocket socket){
        if (wantClientAuth){
            socket.setWantClientAuth(wantClientAuth);
        } else {
            socket.setNeedClientAuth(requireClientAuth);
        }
    }

    /**
     * Configures the given SSL server socket with the requested cipher suites,
     * protocol versions, and need for client authentication
     */
    private void initServerSocket(ServerSocket ssocket) {

        SSLServerSocket socket = (SSLServerSocket) ssocket;

        if (enabledCiphers != null) {
            socket.setEnabledCipherSuites(enabledCiphers);
        }

        String[] requestedProtocols = endpoint.getSslEnabledProtocolsArray();
        setEnabledProtocols(socket, getEnabledProtocols(socket, 
                                                         requestedProtocols));

        // we don't know if client auth is needed -
        // after parsing the request we may re-handshake
        configureClientAuth(socket);
    }

    /**
     * Checks that the certificate is compatible with the enabled cipher suites.
     * If we don't check now, the JIoEndpoint can enter a nasty logging loop.
     * See bug 45528.
     */
    private void checkConfig() throws IOException {
        // Create an unbound server socket
        ServerSocket socket = sslProxy.createServerSocket();
        initServerSocket(socket);

        try {
            // Set the timeout to 1ms as all we care about is if it throws an
            // SSLException on accept. 
            socket.setSoTimeout(1);

            socket.accept();
            // Will never get here - no client can connect to an unbound port
        } catch (SSLException ssle) {
            // SSL configuration is invalid. Possibly cert doesn't match ciphers
            IOException ioe = new IOException(sm.getString(
                    "jsse.invalid_ssl_conf", ssle.getMessage()));
            ioe.initCause(ssle);
            throw ioe;
        } catch (Exception e) {
            /*
             * Possible ways of getting here
             * socket.accept() throws a SecurityException
             * socket.setSoTimeout() throws a SocketException
             * socket.accept() throws some other exception (after a JDK change)
             *      In these cases the test won't work so carry on - essentially
             *      the behaviour before this patch
             * socket.accept() throws a SocketTimeoutException
             *      In this case all is well so carry on
             */
        } finally {
            // Should be open here but just in case
            if (!socket.isClosed()) {
                socket.close();
            }
        }
        
    }

    @Override
    public void configureSessionContext(SSLSessionContext sslSessionContext) {
        int sessionCacheSize;
        if (endpoint.getSessionCacheSize() != null) {
            sessionCacheSize = Integer.parseInt(
                    endpoint.getSessionCacheSize());
        } else {
            sessionCacheSize = defaultSessionCacheSize;
        }

        int sessionTimeout;
        if (endpoint.getSessionTimeout() != null) {
            sessionTimeout = Integer.parseInt(endpoint.getSessionTimeout());
        } else {
            sessionTimeout = defaultSessionTimeout;
        }

        sslSessionContext.setSessionCacheSize(sessionCacheSize);
        sslSessionContext.setSessionTimeout(sessionTimeout);
    }

    @Override
    public SSLContext createSSLContext() throws Exception {

        // SSL protocol variant (e.g., TLS, SSL v3, etc.)
        String protocol = endpoint.getSslProtocol();
        if (protocol == null) {
            protocol = defaultProtocol;
        }

        SSLContext context = SSLContext.getInstance(protocol);

        return context;
    }


    @Override
    public KeyManager[] getKeyManagers() throws Exception {
        String keystoreType = endpoint.getKeystoreType();
        if (keystoreType == null) {
            keystoreType = defaultKeystoreType;
        }

        String algorithm = endpoint.getAlgorithm();
        if (algorithm == null) {
            algorithm = KeyManagerFactory.getDefaultAlgorithm();
        }

        return getKeyManagers(keystoreType, endpoint.getKeystoreProvider(),
                algorithm, endpoint.getKeyAlias());
    }

    @Override
    public TrustManager[] getTrustManagers() throws Exception {
        String truststoreType = endpoint.getTruststoreType();
        if (truststoreType == null) {
            truststoreType = System.getProperty("javax.net.ssl.trustStoreType");
        }
        if (truststoreType == null) {
            truststoreType = endpoint.getKeystoreType();
        }
        if (truststoreType == null) {
            truststoreType = defaultKeystoreType;
        }

        String algorithm = endpoint.getTruststoreAlgorithm();
        if (algorithm == null) {
            algorithm = TrustManagerFactory.getDefaultAlgorithm();
        }

        return getTrustManagers(truststoreType, endpoint.getKeystoreProvider(),
                algorithm);
    }

}
