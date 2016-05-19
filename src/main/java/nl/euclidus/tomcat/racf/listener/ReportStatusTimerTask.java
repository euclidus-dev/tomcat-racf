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

import java.util.TimerTask;
import java.util.logging.Logger;

import static nl.euclidus.tomcat.racf.RTAConstants.*;

/**
 * A {@link TimerTask} implementation that regularly reports the UP status of a tomcat instance to the master tomcat console
 * 
 * @author Harry Metske
 * @author Gerard Borst
 *
 */
public class ReportStatusTimerTask extends TimerTask {
	private static final Logger log = Logger.getLogger(ReportStatusTimerTask.class.getName());

	

	/* (non-Javadoc)
	 * @see java.util.TimerTask#run()
	 */
	@Override
	public void run() {
		boolean success = TomcatStatusReporter.setStatus(TOMCAT_STATUS.STARTED.toString(), INSTANCE_NAME, SERVER, WS_URI, SERVER_INFO);
		if (success) {
			log.info("Instance (" + INSTANCE_NAME + ") on lpar " + SERVER + " reported status as \"" + TOMCAT_STATUS.STARTED.toString() + "\" to WS_URI " + WS_URI);
			this.cancel();
		}
	}

}
