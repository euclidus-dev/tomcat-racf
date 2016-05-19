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

import java.util.HashMap;

/**
 * Utility class to convert Unix System Services errno/errno2 to a descent String.
 * More information on these codes can be found at :
 * - 
 * - SYS1.MACLIB(BPXYERNO)
 * 
 * IBM fails to provide decent message with their retun/reason codes, so we do it here
 * 
 * This class only provides messages for the most occurring return codes and reason codes, so it is not exhausting
 * 
 * @author metskeh
 *
 */
public class StringErrNo {
	public static final int RETURNCODE_EINVAL = 121;
	public static final int RETURNCODE_EPERM = 139;
	public static final int RETURNCODE_EACCES = 111;
	public static final int RETURNCODE_EMVSEXPIRE = 168;
	public static final int RETURNCODE_EMVSSAFEXTRERR = 163;
	public static final int RETURNCODE_EMVSSAF2ERR = 164;
	public static final int RETURNCODE_ESRCH = 143;

	public static final String RETURN_CODE_UNKNOWN = "UNKNOWN RETURN CODE";
	public static final String REASON_CODE_UNKNOWN = "UNKNOWN REASON CODE";

	public static final String CONSULT_REASONCODE = "consult the reason codes";

	public static final int REASONCODE_JRUSERNAMELENERROR =151782054 ;  // 678
	public static final int REASONCODE_JRPASSWORDLENERROR = 151782055; // 679
	public static final int REASONCODE_JRNEWPASSWORDLENERROR = 151782056 ;  // 680
	public static final int REASONCODE_JRUSERNAMEBAD = 151782288;// 912

	private static HashMap<Integer, String> returnCodeTable = null;

	static {
		returnCodeTable = new HashMap<Integer, String>();
		returnCodeTable.put(RETURNCODE_EINVAL, CONSULT_REASONCODE);
		returnCodeTable.put(RETURNCODE_EPERM, "The caller does not have read access to the BPX.DAEMON resource in the FACILITY class.");
		returnCodeTable.put(RETURNCODE_EACCES, "The password specified is not authorized, access is denied.");
		returnCodeTable.put(RETURNCODE_EMVSEXPIRE, "The password has expired.");
		returnCodeTable.put(RETURNCODE_EMVSSAFEXTRERR, "The user's access has been revoked.");
		returnCodeTable.put(RETURNCODE_EMVSSAF2ERR, "The RACF Get UMAP service had an error.");
		returnCodeTable.put(RETURNCODE_ESRCH, "The user name specified could not be found.");
	}

	private static HashMap<Integer, String> reasonCodeTable = null;

	static {
		reasonCodeTable = new HashMap<Integer, String>();
		reasonCodeTable.put(REASONCODE_JRUSERNAMELENERROR, "The user name length value was incorrect.");
		reasonCodeTable.put(REASONCODE_JRPASSWORDLENERROR, "The password length value was incorrect.");
		reasonCodeTable.put(REASONCODE_JRNEWPASSWORDLENERROR, "The new password length value was incorrect.");
		reasonCodeTable.put(REASONCODE_JRUSERNAMEBAD, "The user name is not a valid z/OS user name.");
	}

	public static String getStringforReasonAndReturnCode(int returnCode, int reasonCode) {
		if (returnCodeTable.get(returnCode) == null) {
			return RETURN_CODE_UNKNOWN;
		}

		if (returnCodeTable.get(returnCode).equals(CONSULT_REASONCODE)) {
			if (reasonCodeTable.get(reasonCode) == null) {
				return REASON_CODE_UNKNOWN;
			}
			return reasonCodeTable.get(reasonCode);
		}

		return returnCodeTable.get(returnCode);
	}
}
