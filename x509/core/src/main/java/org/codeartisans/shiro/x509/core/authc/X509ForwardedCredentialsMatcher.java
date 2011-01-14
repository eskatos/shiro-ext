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

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class X509ForwardedCredentialsMatcher
        implements CredentialsMatcher
{

    private static final Logger LOGGER = LoggerFactory.getLogger( X509CredentialsSha256Matcher.class );

    @Override
    public boolean doCredentialsMatch( AuthenticationToken token, AuthenticationInfo info )
    {
        throw new UnsupportedOperationException( "Not supported yet." );
    }

}
