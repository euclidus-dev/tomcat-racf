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

import java.io.IOException;

import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.authenticator.BasicAuthenticator;
import org.apache.catalina.connector.Request;
import org.apache.catalina.deploy.LoginConfig;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

/**
 * Racf Basic Authenticator with redirect for expired accounts.
 * 
 * activate with valve in Context:
 * <br><br>
<br>&ltValve className=”nl.euclidus.tomcat.racf.auth.realm.RacfBasicAuthenticator”
 * <br>changePasswordUrl="http://&ltcomplete url of changepassword function&gt" /&gt
 * @author borstg
 *
 */

public class RacfBasicAuthenticator extends BasicAuthenticator {
	private static final Log log = LogFactory.getLog(RacfBasicAuthenticator.class);
	private String changePasswordUrl;

	@Override
	public boolean authenticate(Request request, HttpServletResponse response,
			LoginConfig config) throws IOException {
		boolean authenticated = super.authenticate(request, response, config);
		
		if (authenticated 
				&& request.getUserPrincipal() != null 
				&& request.getUserPrincipal().getName() != null 
				&& request.getUserPrincipal().getName().equals(RACFRealm.USER_IS_EXPIRED)) {
			log.info("Expired password, redirect to: "+ changePasswordUrl);	
			response.sendRedirect(changePasswordUrl);
			return false;
		}
		return authenticated;
	}

	public String getChangePasswordUrl() {
		return changePasswordUrl;
	}

	public void setChangePasswordUrl(String changePasswordUrl) {
		this.changePasswordUrl = changePasswordUrl;
	}
	
    @Override
    protected synchronized void startInternal() throws LifecycleException {
        
        if (changePasswordUrl == null) {
        	throw new LifecycleException("Parameter changePasswordUrl in RacfBasicAuthenticator Valve not initialized");
        }

        super.startInternal();
    }
}
