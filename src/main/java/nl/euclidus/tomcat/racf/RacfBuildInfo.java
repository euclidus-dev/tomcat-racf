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

import java.util.ResourceBundle;



/**
 * 
 * @author Gerard Borst
 *
 */
public class RacfBuildInfo {
	static final org.apache.juli.logging.Log log = org.apache.juli.logging.LogFactory
			.getLog(RacfBuildInfo.class);
	private static String buildDate = null;
	private static String buildRelease = null;

	static {
		ResourceBundle res = ResourceBundle.getBundle(BUNDLE_NAME);
		buildDate = res.getString(JAR_BUILD_DATE);
		buildRelease = res.getString(JAR_BUILD_RELEASE);
	}
	
	public static String getBuildDate() {	

		return buildDate;
	}

	public static String getBuildRelease() {
		return buildRelease;
	}

	public static void printInfo() {
		System.out.println("Build Date: " + getBuildDate());
		System.out.println("Build Release: " + getBuildRelease());		
	}
}
