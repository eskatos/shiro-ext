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
package org.codeartisans.shiro.x509.core.authc;

public class X509CredentialsSujbectDNMatcher
        extends AbstractX509CredentialsMatcher
{

    @Override
    public boolean doX509CredentialsMatch( X509AuthenticationToken token, X509AuthenticationInfo info )
    {
        boolean match = doEquals( token.getSubjectDN(), info.getIssuerDN() );

        if ( match ) {
            LOGGER.trace( "Client SubjectDN match the one provided by the Realm, will return true" );
        } else if ( LOGGER.isTraceEnabled() ) {
            LOGGER.trace( "Client SubjectDN ({}) do not match the one provided by the Realm ({}), will return false",
                          toString( token.getSubjectDN() ), toString( info.getIssuerDN() ) );
        }

        return match;
    }

}
