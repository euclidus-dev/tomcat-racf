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
package nl.euclidus.tomcat.racf.listener;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.logging.Logger;

import org.apache.catalina.util.ServerInfo;

import static nl.euclidus.tomcat.racf.RTAConstants.*;

/**
 * Utility type class that reports status to master tomcat.
 * 
 * Called by the {@link TomcatServerLifecycleListener} and the {@link ReportStatusTimerTask}
 * 
 * @author Harry Metske
 * @author Gerard Borst
 *
 */
public class TomcatStatusReporter {

	private static final Logger log = Logger.getLogger(TomcatStatusReporter.class.getName());

	/**
	 * @param status the status to be reported
	 * @param instName the name of the tomcat instance
	 * @param lpar the name of the lpar
	 * @param wsUri the target address where the status should be reported
	 * 
	 * @return true if the actino was succesful, false if it failed to report the status (master tomcat unreachable for instance)
	 */
	static boolean setStatus(String status, String instName, String lpar, String wsUri, String serverInfo) {

		try {
			HttpURLConnection conn = null;

			String payload = String.format(SET_STATUS_XML, instName, lpar, status, serverInfo);

			// Send the request
			conn = getConnection(wsUri, "PUT");
			conn.setRequestProperty("accept", "text/xml");
			DataOutputStream out = new DataOutputStream(conn.getOutputStream());
			out.writeBytes(payload);
			out.flush();
			getResponse(conn);
			return true;
		} catch (IOException e) {
			log.warning("Failed to report status " + status +  " for Instance (" + instName + ") on lpar " + lpar + " to WS_URI " + wsUri + ", reason:" + e.getMessage());
			return false;
		}
	}

	private static HttpURLConnection getConnection(String url_string, String verb) throws IOException {
		HttpURLConnection conn = null;
		URL url = new URL(url_string);
		conn = (HttpURLConnection) url.openConnection();
		conn.setRequestMethod(verb);
		conn.setDoInput(true);
		conn.setDoOutput(true);
		return conn;
	}

	private static void getResponse(HttpURLConnection conn) throws IOException {
		StringBuffer xml = new StringBuffer();
		BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
		String next = null;
		while ((next = reader.readLine()) != null)
			xml.append(next);
	}

	/**
	 * Method for test.
	 * @param args
	 */
	public static void main(String[] args) {
		String instName = "TMCT001";
		String lpar = "XAT1";
		String wsUri = "http://localhost:9080/rta/status_service/";
		String status = TOMCAT_STATUS.STARTED.toString();
		String serverInfo = ServerInfo.getServerInfo();

		TomcatStatusReporter.setStatus(status, instName, lpar, wsUri, serverInfo);
	}

}
