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

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import java.security.InvalidParameterException;

import nl.euclidus.tomcat.racf.RacfConstants;

import org.apache.tomcat.util.net.AbstractEndpoint;
import org.apache.tomcat.util.net.jsse.JSSESocketFactory;
import org.apache.tomcat.util.res.StringManager;


/**
 * RACF SSL server socket factory. It <b>requires</b> a valid RSA key in RACF 
 * <br/>
 * 
 * 
 * @author Gerard Borst
 */
public class RACFJSSESocketFactory extends JSSESocketFactory {

    private static final StringManager sm =
        StringManager.getManager("nl.euclidus.tomcat.racf.res");
    
    static final org.apache.juli.logging.Log log =
        org.apache.juli.logging.LogFactory.getLog(RACFJSSESocketFactory.class);

    private AbstractEndpoint<?> endpoint;

    // Defaults - made public where re-used
    private static final String defaultRacfKeystoreType = RacfConstants.RACF_SSL_DEFAULT_KEYSTORE_TYPE;
    private static final String racfKeystoreProvider = RacfConstants.RACF_SSL_KEYSTORE_PROVIDER;

    public RACFJSSESocketFactory (AbstractEndpoint<?> endpoint) {
    	super(endpoint);
    	this.endpoint = endpoint;
    	if (endpoint.getProperty(RacfConstants.RACF_SSL_ATTR_KEY_LABEL) != null)
    		this.endpoint.setKeyAlias((endpoint.getProperty(RacfConstants.RACF_SSL_ATTR_KEY_LABEL)));
    	String keyStore = this.endpoint.getKeystoreType();
    	if (keyStore != null && !RacfConstants.SUPPORTED_KEYSTORES.contains(keyStore)) {
    		this.endpoint.setKeystoreType(defaultRacfKeystoreType);
    		log.debug(sm.getString("jsse.keystore_type_set", defaultRacfKeystoreType));
    	}
    	String trustStore = this.endpoint.getTruststoreType();
    	if (trustStore != null && !RacfConstants.SUPPORTED_KEYSTORES.contains(trustStore)) {
    		this.endpoint.setTruststoreType(defaultRacfKeystoreType);
    		log.debug(sm.getString("jsse.keystore_type_set", defaultRacfKeystoreType));
    	}
    	if (this.endpoint.getKeystoreProvider() == null)
    		this.endpoint.setKeystoreProvider(racfKeystoreProvider);
    	if (this.endpoint.getTruststoreProvider() == null)
    		this.endpoint.setTruststoreProvider(racfKeystoreProvider);
    	if (this.endpoint.getKeystorePass() == null)
    		this.endpoint.setKeystorePass("password");
    	log.debug("SSL Type: " + this.endpoint.getKeystoreType() 
		+ " Provider: " + this.endpoint.getKeystoreProvider() 
		+ " passw: " + this.endpoint.getKeystorePass()
		+ " alias/label: " + this.endpoint.getKeyAlias());
    }
    
    @Override
    public KeyManager[] getKeyManagers() throws Exception {
        String keystoreType = endpoint.getKeystoreType();
        if (keystoreType == null) {
            keystoreType = defaultRacfKeystoreType;
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
            truststoreType = defaultRacfKeystoreType;
        }

        String algorithm = endpoint.getTruststoreAlgorithm();
        if (algorithm == null) {
            algorithm = TrustManagerFactory.getDefaultAlgorithm();
        }

        return getTrustManagers(truststoreType, endpoint.getKeystoreProvider(),
                algorithm);
    }

    
    /*
     * Gets the SSL server's keystore.
     */
    @Override
    protected KeyStore getKeystore(String type, String provider, String pass)
            throws IOException {
    	String keyRing = endpoint.getProperty(RacfConstants.RACF_SSL_ATTR_KEYRING);
    	log.debug("SSL Type: " + type + " Provider: " + provider + " keyRing: " + keyRing + " pass: " + pass);
        if (keyRing == null)
            keyRing = RacfConstants.RACF_SSL_KEYRING_DEFAULT_VALUE;
    	return getStore(type, provider, keyRing);
    }

    /*
     * Gets the SSL server's truststore.
     */
    @Override
    protected KeyStore getTrustStore(String keystoreType,
            String keystoreProvider) throws IOException {
    	String keyRing = endpoint.getProperty(RacfConstants.RACF_SSL_ATTR_KEYRING);
    	log.debug("SSL Type: " + keystoreType + " Provider: " + keystoreProvider);
        if (keyRing == null)
            keyRing = RacfConstants.RACF_SSL_KEYRING_DEFAULT_VALUE;
    	return getStore(keystoreType, keystoreProvider, keyRing);
    }

    /*
     * Gets the key- or truststore with the specified type, path, and password.
     */
	private KeyStore getStore(String type, String provider, String keyRing) throws IOException {
		String keyStoreType = type.toUpperCase();
		KeyStore ks = null;
		log.debug("SSL Type: " + keyStoreType + " Provider: " + provider + " Keyring: " + keyRing);
		InputStream istream = null;
		try {
			if (!RacfConstants.SUPPORTED_KEYSTORES.contains(keyStoreType)) {
				log.error(sm.getString("jsse.invalid_ssl_conf", 
							"Keystore type " + keyStoreType + "not supported"));
				throw new InvalidParameterException(sm.getString("jsse.invalid_ssl_conf", 
							"Keystore type " + keyStoreType + "not supported"));
			}				
			
			ks = KeyStore.getInstance(keyStoreType, RacfConstants.RACF_SSL_KEYSTORE_PROVIDER);			
			
			istream = RacfConstants.SUPPORTED_KEYSTORES.getRacfInputStream(RacfConstants.SUPPORTED_KEYSTORES.valueOf(keyStoreType), keyRing);

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
}
