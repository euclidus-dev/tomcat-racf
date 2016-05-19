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

import java.util.Timer;
import java.util.logging.Logger;

import nl.euclidus.tomcat.racf.RTAConstants;
import nl.euclidus.tomcat.racf.RTABuildInfo;
import static nl.euclidus.tomcat.racf.RTAConstants.*;

import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleEvent;
import org.apache.catalina.LifecycleListener;
import org.apache.tomcat.util.res.StringManager;

/**
 * This LifeCycleListener traps the {@link org.apache.catalina.Lifecycle#AFTER_START_EVENT} and the
 * {@link org.apache.catalina.Lifecycle#AFTER_STOP_EVENT}.
 * These events are used to report the tomcat instance status to the "Tomcat Admin Application" using
 * a URL connection.
 * The parameters for the URL connection are grabbed from three Java System properties:
 * - tomcat.instance_name
 * - tomcat.lpar
 * - tomcat.mgr_ws_uri  
 * 
 * @author Gerard Borst
 * @author Harry Metske
 *
 */
public class TomcatServerLifecycleListener implements LifecycleListener {
	private static final Logger log = Logger.getLogger(TomcatServerLifecycleListener.class.getName());
	private static final StringManager sm =
        StringManager.getManager("nl.euclidus.tomcat.racf.res");
	
	private static Timer timer  = new Timer("Tomcat Report Status Timer");
	private static Long interval;
	private static ReportStatusTimerTask task = new ReportStatusTimerTask();

	static {
		// Display build info on console
		log.info(sm.getString("logging.info.build_date", RacfBuildInfo.getBuildDate()));
		log.info(sm.getString("logging.info.build_release", RacfBuildInfo.getBuildRelease()));
		
		log.info(sm.getString("logging.info.status", TomcatServerLifecycleListener.class.getName()));
		interval = DEFAULT_INTERVAL;
		if (INTERVAL_STRING != null) {
			try {
				interval = new Long(INTERVAL_STRING);
			} catch (NumberFormatException nfe) {
				log.severe("Could not parse property tomcat.reportstatus.interval, reason : " + nfe.getMessage());
				log.severe("Using default value " + DEFAULT_INTERVAL);
			}
		}
	}

	@Override
	public void lifecycleEvent(LifecycleEvent event) {
		if (Lifecycle.AFTER_START_EVENT.equals(event.getType())) {
			if (TomcatStatusReporter.setStatus(RacfConstants.TOMCAT_STATUS.STARTED.toString(), INSTANCE_NAME, SERVER, WS_URI, SERVER_INFO)) {
				log.info("Instance (" + INSTANCE_NAME + ") on lpar " + SERVER + " reported status as \"" + RacfConstants.TOMCAT_STATUS.STARTED.toString() + "\" to WS_URI " + WS_URI);
			} else {
				//Set status failed
				//Schedule Timer to report in the background.
				timer.scheduleAtFixedRate(task, interval, interval);
				log.warning("Tomcat Report Status TimerTask started with interval " + interval + " milliseconds (user Java System property \"tomcat.reportstatus.interval\" to specify a custom interval)");
			}
		} else {
			if (Lifecycle.AFTER_DESTROY_EVENT.equals(event.getType())) {
				if (TomcatStatusReporter.setStatus(RacfConstants.TOMCAT_STATUS.STOPPED.toString(), INSTANCE_NAME, SERVER, WS_URI, SERVER_INFO)) {
					log.info("Instance (" + INSTANCE_NAME + ") on lpar " + SERVER + " reported status as \"" + RacfConstants.TOMCAT_STATUS.STOPPED.toString() + "\" to WS_URI "
							+ WS_URI);
				}

				//  stop the timer task 
				timer.cancel();

			} else {
				log.info("Ignoring event " + event.getType());
			}
		}
	}

}
