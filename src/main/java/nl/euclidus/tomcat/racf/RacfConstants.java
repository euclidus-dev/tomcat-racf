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
package nl.euclidus.tomcat.racf;

import java.io.IOException;
import java.io.InputStream;

/**
 * All Constants for the Tomcat Infra
 * 
 * @author Harry Metske
 * @author Gerard Borst
 *
 */
public class RacfConstants {	
    /**
     * SSL Attributes
     */
    public static final int SSL_DEFAULT_SESSION_CACHESIZE = 0;
    public static final int SSL_DEFAULT_SESSION_TIMEOUT = 86400;
    public static final String SSL_ALLOW_ALL_SUPPORTED_CIPHERS = "ALL";
    //Not used, only filling
    public static final String SSL_KEY_PASSWORD = "password";
    
	/**
     * RACF SSL Attributes
     */
    public static final String RACF_SSL_ATTR_KEYRING = "keyRing";
    public static final String RACF_SSL_ATTR_KEY_LABEL = "keyLabel";
    public static final String RACF_SSL_KEYRING_DEFAULT_VALUE = "DefaultRing";
    public static final String SSL_DEFAULT_PROTOCOL = "TLS";
    public static final String RACF_SSL_DEFAULT_KEYSTORE_TYPE = "JCERACFKS";
    public static final String RACF_SSL_KEYSTORE_PROVIDER = "IBMJCE";
    
    public static enum SUPPORTED_KEYSTORES {
    	JCERACFKS, JCECCARACFKS;
    	/**
    	 * Is the keystore type supported?
    	 * <br>
    	 * Only IBM Racf Types are supported
    	 * @param type
    	 * @return
    	 */
    	public static boolean contains(String type) {
    		try {
    			SUPPORTED_KEYSTORES.valueOf(type);
    			return true;
    		} catch (IllegalArgumentException e) {
    			return false;
    		}
    	}
    	
    	/**
    	 * Returns the Inputstream for the different types.
    	 * 
    	 * @param type On of the supported types
    	 * @param keyRing The RACF Keyring
    	 * @return The {@code RacfInputStream} for this type
    	 * @throws IOException
    	 */
    	public static InputStream getRacfInputStream(SUPPORTED_KEYSTORES type, String keyRing) throws IOException {    	
    		switch (type) {
    		case JCERACFKS : 
    			return new com.ibm.crypto.provider.RACFInputStream(System.getProperty("user.name"), keyRing, null);
    		case JCECCARACFKS: return new com.ibm.crypto.hdwrCCA.provider.RACFInputStream(System.getProperty("user.name"), keyRing, null);
    		default: return null;
    		}
    	}
	}
    
    /**
     * Name of context-param to disable prefixing roles with server account.
     */
    public static final String PRF_ROLE_WTH_USER = "prefix_role_with_user";
}
