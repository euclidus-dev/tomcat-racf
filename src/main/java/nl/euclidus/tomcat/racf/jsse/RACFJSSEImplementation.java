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


import org.apache.tomcat.util.net.AbstractEndpoint;
import org.apache.tomcat.util.net.ServerSocketFactory;
import org.apache.tomcat.util.net.jsse.JSSEImplementation;

/** JSSEImplementation:

Concrete implementation class for IBM Security Server JSSE.


@author EKR and Gerard Borst


* SSLImplementation for IBM Security Server.
* <br><br>
* Example Connector definition:<br>
* <pre>&ltConnector SSLImplementation="nl.euclidus.tomcat.racf.jsse.RACFJSSEImplementation"
*           address="&lthost name&gt"
*           port="8443" protocol="HTTP/1.1" SSLEnabled="true"
*           maxThreads="150" scheme="https" secure="true"
*           keyRing="&ltracf keyring&gt"
*           keyLabel="&ltracf key label&gt"
*           keystoreType="JCERACFKS"
*           keystoreProvider="IBMJCE"
*           clientAuth="false" sslProtocol="TLS"/&gt
* 
* @author EKR and Gerard Borst
* 
*/

public class RACFJSSEImplementation extends JSSEImplementation {
	
    @Override
    public ServerSocketFactory getServerSocketFactory(AbstractEndpoint<?> endpoint)  {
        return new RACFJSSESocketFactory(endpoint);
    }

	@Override
	public String getImplementationName() {
		return "RACFJSSE";
	}
}
