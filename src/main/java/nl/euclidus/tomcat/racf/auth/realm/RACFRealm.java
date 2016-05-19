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
package nl.euclidus.tomcat.racf.auth.realm;

import java.beans.PropertyChangeListener;
import java.security.Principal;
import java.security.cert.X509Certificate;

import nl.euclidus.tomcat.racf.auth.login.RACFPrincipal;
import nl.euclidus.tomcat.racf.auth.login.StringErrNo;
import static nl.euclidus.tomcat.racf.RTAConstants.*;

import org.apache.catalina.Wrapper;
import org.apache.catalina.realm.RealmBase;

import com.ibm.os390.security.PlatformAccessControl;
import com.ibm.os390.security.PlatformAccessLevel;
import com.ibm.os390.security.PlatformReturned;
import com.ibm.os390.security.PlatformUser;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

/**
 * Change History: 01-sep-06 : MetskeH : Initial Version 04-oct-06 : MetskeH :
 * change the name of the EJBROLE profile that is checked (prepend userid.)
 * 07-mei-07 : MetskeH : remove password from log string, change some debug
 * statements and levels 29-dec-08 : MetskeH : replaced log4j with JUL to get
 * rid of log4j dependency 02-feb-11 : BorstG : Wrapper usage in hasRole and
 * removed authenticate(String, byte[])
 * 
 * @author MetskeH
 */

public class RACFRealm extends RealmBase {

	public static final String USER_IS_EXPIRED = "userIsExpired";

	private static final Log log = LogFactory.getLog(RACFRealm.class);

	private String OS = System.getProperty("os.name");

	/**
	 * Descriptive information about this Realm implementation.
	 * 
	 * This Realm uses SAF to perform userid/pw checking and role checking.
	 * Roles are checked against EJBROLE class profiles
	 * 
	 * See http://www-03.ibm.com/servers/eserver/zseries/software/java/security.
	 * html for more info
	 * 
	 * Check "UNIX System Services Messages and Codes" for reason codes
	 */
	protected final String info = "org.apache.catalina.realm.auth.RACFRealm/1.0";

	@Override
	public String getInfo() {
		return info;
	}

	@Override
	public Principal authenticate(String username, String credentials) {
		log.debug("authenticate() called with parms: " + username
				+ " , (password hidden)");
		if (username == null) {
			log.error("username can not be null !");
			return null;
		}
		if (credentials == null) {
			log.error("credentials can not be null !");
			return null;
		}
		PlatformReturned platform = PlatformUser.authenticate(username,
				credentials);
		// if a null is returned, then it means a successful auth.
		if (platform != null) {
			String errno = Integer.toHexString(platform.errno).toUpperCase();
			String errno2 = Integer.toHexString(platform.errno2).toUpperCase();
			log.error("RACF authentication failed, user=" + username
					+ " , errno=" + errno + " (hex) , errno2=" + errno2
					+ " (hex), error message: " + platform.errnoMsg);
			// password expired?
			if (platform.errno == StringErrNo.RETURNCODE_EMVSEXPIRE) {
				log.error("Password expired, user=" + username);
				// set racf principal with name USER_IS_EXPIRED
				// as a token for Authenticator
				return new RACFPrincipal(USER_IS_EXPIRED, credentials);
			}
			return null;
		}
		log.debug("RACF authentication successful");
		return new RACFPrincipal(username, credentials);
		//
	}

	@Override
	public Principal authenticate(String username, String digest, String nonce,
			String nc, String cnonce, String qop, String realm, String md5a2) {
		log.debug("This method has not been implemented");
		return null;
	}

	@Override
	public Principal authenticate(X509Certificate[] certs) {
		log.debug("This method has not been implemented");
		return null;
	}

	@Override
	public void backgroundProcess() {
		log.debug("This method has not been implemented");
	}

	@Override
	public boolean hasRole(Wrapper wrapper, Principal principal, String role) {
		if ("*".equals(role)) {
			return true;
		} else if (role == null) {
			return false;
		}

		boolean prefixRoleWithUser = true;

		if (wrapper != null) {
			String roleParam = wrapper.getServlet().getServletConfig()
					.getServletContext().getInitParameter(PRF_ROLE_WTH_USER);
			log.debug("roleParam = " + roleParam);
			if (roleParam != null && roleParam.equals("false"))
				prefixRoleWithUser = false;

			// Check for a role alias defined in a <security-role-ref> element
			String realRole = wrapper.findSecurityReference(role);
			if (realRole != null)
				role = realRole;
		}
		//
		// if this Realm is active, also the tomcat "manager" and "admin" role
		// (from the default supplied Tomcat manager and host-manager
		// application) is checked,
		// now if we want to run multiple copies of tomcat, we want to validate
		// against different EJBROLE class profiles
		// so what we do is prepend the userid of the current job to the profile
		// , example :
		// manager ==> WIKI00U.manager
		// we do this, so we can keep these files unchanged (in the clone-set):
		// - /usr/local/tomcat/webapps/manager/WEB-INF/web.xml
		// - /usr/local/tomcat/webapps/host-manager/WEB-INF/web.xml
		//
		if (prefixRoleWithUser) {
			String userid = System.getProperty("user.name").toUpperCase();
			log.debug("Role is prefixed with: " + userid);
			role = userid + "." + role;
		}
		log.debug("Role = " + role);
		//

		try {
			log.debug("hasRole() called with parms: " + principal.getName()
					+ " , " + role);
			// only on the z/OS platform we can do a native RACF call:
			if ("z/OS".equals(OS)) {
				//
				PlatformReturned platform = PlatformAccessControl
						.checkPermission(principal.getName(), "EJBROLE", role,
								PlatformAccessLevel.READ);
				// if a null is returned, then it means a successful auth.
				if (platform == null) {
					log.debug("role checking for role " + role + " successful");
					return true;
				}
				String errno = Integer.toHexString(platform.errno)
						.toUpperCase();
				String errno2 = Integer.toHexString(platform.errno2)
						.toUpperCase();
				log.error("RACF Role checking failed for user="
						+ principal.getName() + " , role=" + role
						+ " (RACF class EJBROLE), errno=" + errno
						+ " (hex), errno2=" + errno2
						+ " (hex), error message: " + platform.errnoMsg);
			} else {
				log.error("this realm implementation can only be used on the z/OS operating system because it needs SAF !");
				return false;
			}
		} catch (Exception e) {
			log.error("exception occurred during role checking: " + e);
			e.printStackTrace();
		}
		return false;
	}

	@Override
	public void removePropertyChangeListener(PropertyChangeListener listener) {
		support.removePropertyChangeListener(listener);

	}

	@Override
	protected String getName() {
		return this.info;
	}

	@Override
	protected String getPassword(String username) {
		log.debug("This method has not been implemented");
		return null;
	}

	@Override
	protected Principal getPrincipal(String username) {
		log.debug("This method has not been implemented");
		return null;
	}

}