/*
 * Copyright (c) 2011, Paul Merlin. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package org.apache.shiro.authc.x509;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class X509CredentialsIssuerDNSNMatcher
        extends AbstractX509CredentialsMatcher
{

    private static final Logger LOGGER = LoggerFactory.getLogger( X509CredentialsIssuerDNSNMatcher.class );

    @Override
    public boolean doX509CredentialsMatch( X509AuthenticationToken token, X509AuthenticationInfo info )
    {
        boolean match = token.getHexSerialNumber().equals( info.getHexSerialNumber() )
                        && doEquals( token.getIssuerDN(), info.getIssuerDN() );

        if ( match ) {
            LOGGER.trace( "Client IssuerDN and Serial Number match the ones provided by the Realm, will return true" );
        } else if ( LOGGER.isTraceEnabled() ) {
            LOGGER.trace( "Client IssuerDN ({}) or Serial Number ({}) do not match the one provided by the Realm ({} / {}), will return false",
                          new Object[]{ toString( token.getIssuerDN() ), token.getHexSerialNumber(), toString( info.getIssuerDN() ), info.getHexSerialNumber() } );
        }

        return match;
    }

}
