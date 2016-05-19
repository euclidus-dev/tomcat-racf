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

import static nl.euclidus.tomcat.racf.RTAConstants.*;

import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleEvent;

import com.ibm.jzos.MvsConsole;
import com.ibm.jzos.WtoMessage;

public class TomcatZOSServerLifecycleListener extends TomcatServerLifecycleListener {
	public void lifecycleEvent(LifecycleEvent event) {
		super.lifecycleEvent(event);
		//write messages to z/OS system log
		if (Lifecycle.BEFORE_START_EVENT.equals(event.getType())) {
			writeToSysLog(MSG_TMCT_STARTING);
		} else {
			if (Lifecycle.AFTER_START_EVENT.equals(event.getType())) {
				writeToSysLog(MSG_TMCT_STARTED);
			} else {
				if (Lifecycle.BEFORE_STOP_EVENT.equals(event.getType())) {
					writeToSysLog(MSG_TMCT_STOPPING);
				} else {
					if (Lifecycle.AFTER_DESTROY_EVENT.equals(event.getType())) {
						writeToSysLog(MSG_TMCT_STOPPED);
					}
				}
			}
		}		
	}
	
	public void writeToSysLog(String msg) {
		String formed_msg = String.format(msg, SERVER, INSTANCE_NAME);
		WtoMessage mymessage = new WtoMessage(formed_msg);
		MvsConsole.wto(mymessage);
	}
}
