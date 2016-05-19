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
package nl.euclidus.tomcat.racf.auth.login;

import java.io.Serializable;
import java.security.Principal;

/**
 * A simple Principal containing userid.
 * (maybe more in the future)
 * 
 * @author metskem
 *
 */
public class RACFPrincipal implements Principal, Serializable {
	private static final long serialVersionUID = 1L;
	
	private String userid = null;
	private String credentials = null;

	public RACFPrincipal(String aUserid) {
		setName(aUserid);
	}

	public RACFPrincipal(String aUserid, String credentials) {
		setName(aUserid);
		setCredentials(credentials);
	}

	private void setName(String aUserid) {
		userid = aUserid;
	}

	public String getName() {
		return userid;
	}

	public String getCredentials() {
		return credentials;
	}

	public void setCredentials(String credentials) {
		this.credentials = credentials;
	}

}
