/*
 * Created on 14 janv. 2011
 *
 * Licenced under the Netheos Licence, Version 1.0 (the "Licence"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at :
 *
 * http://www.netheos.net/licences/LICENCE-1.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *
 * Copyright (c) Netheos
 */
package org.codeartisans.shiro.x509.core.authc;

import java.security.cert.CertificateEncodingException;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.crypto.hash.Sha256Hash;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class X509CredentialsSha256Matcher
        implements CredentialsMatcher
{

    private static final Logger LOGGER = LoggerFactory.getLogger( X509CredentialsSha256Matcher.class );

    @Override
    public boolean doCredentialsMatch( AuthenticationToken token, AuthenticationInfo info )
    {
        try {
            X509AuthenticationToken x509AuthToken = ( X509AuthenticationToken ) token;
            X509AuthenticationInfo x509AuthInfo = ( X509AuthenticationInfo ) info;

            String clientCertSha256 = new Sha256Hash( x509AuthToken.getClientX509Certificate().getEncoded() ).toHex();
            String subjectCertSha256 = new Sha256Hash( x509AuthInfo.getSubjectCertificate().getEncoded() ).toHex();

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
