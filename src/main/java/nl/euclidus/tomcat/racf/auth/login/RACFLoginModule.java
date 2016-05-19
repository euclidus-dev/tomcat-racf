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

import java.security.Principal;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.TextOutputCallback;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import com.ibm.os390.security.PlatformReturned;
import com.ibm.os390.security.PlatformUser;

/**
 * This module acts as a JAAS LoginModule and authenticates against SAF (System
 * Authorization Facility) 
 * The caller has to supply a proper CallbackHandler,
 * passing in a userid and password, and catching the loginMessage returned by
 * this module in a TextOutputCallback.
 *
 *@author Harry Metske
 */
public class RACFLoginModule implements LoginModule
{
    private CallbackHandler callbackHandler = null;

    private boolean loginSucceeded = false;
    
    private Subject m_subject=null;
    
    protected Collection<Principal> m_principals;

    @Override
    public boolean commit() throws LoginException {
		if (loginSucceeded) {
			for (Principal principal : m_principals) {
				m_subject.getPrincipals().add(principal);
			}
			return true;
		}
		return false;
	}

    /*
     * (non-Javadoc)
     * @see
     * javax.security.auth.spi.LoginModule#initialize(javax.security.auth.Subject
     * , javax.security.auth.callback.CallbackHandler, java.util.Map,
     * java.util.Map)
     */
    @Override
    public final void initialize(final Subject aSubject, final CallbackHandler aCallbackHandler, final Map<String, ?> aSharedState,
                                 final Map<String, ?> aOptions)
    {
        callbackHandler = aCallbackHandler;
        m_subject = aSubject;
        m_principals = new HashSet<Principal>();
        
        dumpOptions(aOptions);
    }

    /*
     * (non-Javadoc)
     * @see javax.security.auth.spi.LoginModule#login()
     */
    public final boolean login() throws LoginException
    {
        Callback[] callbacks = new Callback[] { new NameCallback("why put something here ?"),
                                               new PasswordCallback("why put something here ?", false) };
        try
        {
            // get the userid and password
            callbackHandler.handle(callbacks);
        }
        catch (Exception e)
        {
            throw new LoginException(e.getMessage());
        }

        String userid = null;
        String password = null;

        // iterate over the supplied callbacks, normally they should contain one
        // NameCallback containing the userid
        // and one PasswordCallback containing the password.
        for (int i = 0; i < callbacks.length; i++)
        {
            if (callbacks[i] instanceof NameCallback)
            {
                userid = ((NameCallback) callbacks[i]).getName();
            }
            else if (callbacks[i] instanceof PasswordCallback)
            {
                password = new String(((PasswordCallback) callbacks[i]).getPassword());
            }
            else
            {
                throw new LoginException("Callback type invalid");
            }
        }

        // This is the actual call to SAF
        PlatformReturned platform = PlatformUser.authenticate(userid, password);

        // if a null is returned, then it means a successful auth. :
        String msg = null;
        if (platform != null)
        {
            String errno = Integer.toHexString(platform.errno);
            String errno2 = Integer.toHexString(platform.errno2);
            
            String rawMsg = "RACF authentication failed, user=" + userid + " , errno=" + errno + " (hex) , errno2=" + errno2
                  + " (hex), error message: " + platform.errnoMsg;
            
            msg = StringErrNo.getStringforReasonAndReturnCode(platform.errno, platform.errno2);
            
            if (msg.equals(StringErrNo.RETURN_CODE_UNKNOWN) || msg.equals(StringErrNo.REASON_CODE_UNKNOWN)) {
				msg = rawMsg;
			}
            
            //
            //  I know this is "not done", but I don't want a dependency on log4j or some other logging framework
            System.err.println(msg);

            // return the message by passing a TextOutputCallback to the
            // callbackHandler
            callbacks = new Callback[] { new TextOutputCallback(TextOutputCallback.ERROR, msg) };
            try
            {
                callbackHandler.handle(callbacks);
            }
            catch (Exception e)
            {
                throw new LoginException(e.getMessage());
            }
            // fail the login
            throw new FailedLoginException(msg);
        }

        loginSucceeded = true;
        // If login succeeds, commit these principals/roles
        m_principals.add( new RACFPrincipal( userid));

        return true;
    }

    public boolean logout() throws LoginException
    {
        //
        // currently doesn't do anything useful
        return false;
    }

    /**
     * Internal method for debugging purposes
     * 
     * @param aOptions
     */
    @SuppressWarnings("unchecked")
	private void dumpOptions(Map<String, ?> aOptions)
    {
        StringBuilder optionsString = new StringBuilder();
        Set<?> entries = aOptions.entrySet();
        for (Object entry : entries)
        {
            optionsString.append(((Map.Entry<String, ?>)entry).getKey() 
            		+ "=" + ((Map.Entry<String, ?>) entry).getValue().toString() + "  ");
        }
    }

    public boolean abort() throws LoginException
    {
        return true;
    }
}
