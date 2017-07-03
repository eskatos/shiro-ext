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

import java.security.cert.CertificateEncodingException;

import org.apache.shiro.crypto.hash.Sha256Hash;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class X509CredentialsSha256Matcher
        extends AbstractX509CredentialsMatcher
{

    private static final Logger LOGGER = LoggerFactory.getLogger( X509CredentialsSha256Matcher.class );

    @Override
    public boolean doX509CredentialsMatch( X509AuthenticationToken token, X509AuthenticationInfo info )
    {
        try {
            String clientCertSha256 = new Sha256Hash( token.getX509Certificate().getEncoded() ).toHex();
            String subjectCertSha256 = new Sha256Hash( info.getX509Certificate().getEncoded() ).toHex();

            boolean match = clientCertSha256.equals( subjectCertSha256 );

            if ( match ) {
                LOGGER.trace( "Client certificate Sha256 hash match the one provided by the Realm, will return true" );
            } else {
                LOGGER.trace( "Client certificate Sha256 hash ({}) do not match the one provided by the Realm ({}), will return false", clientCertSha256, subjectCertSha256 );
            }

            return match;

        } catch ( CertificateEncodingException ex ) {
            LOGGER.trace( "Unable to do credentials matching", ex );
            return false;
        }

    }

}
