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

import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.HostAuthenticationToken;

public class X509ForwardedAuthenticationToken
        implements AuthenticationToken, HostAuthenticationToken
{

    private static final long serialVersionUID = 1L;
    private final X509Certificate clientCertificate;
    private final X500Principal clientSubjectDN;
    private final X500Principal clientIssuerDN;
    private final String clientHexSerialNumber;
    private final String host;

    public X509ForwardedAuthenticationToken( X509Certificate clientCertificate, X500Principal clientSubjectDN, X500Principal clientIssuerDN, String clientHexSerialNumber, String host )
    {
        this.clientCertificate = clientCertificate;
        this.clientSubjectDN = clientSubjectDN;
        this.clientIssuerDN = clientIssuerDN;
        this.clientHexSerialNumber = clientHexSerialNumber;
        this.host = host;
    }

    @Override
    public Object getPrincipal()
    {
        throw new UnsupportedOperationException( "Not supported yet." );
    }

    @Override
    public Object getCredentials()
    {
        throw new UnsupportedOperationException( "Not supported yet." );
    }

    @Override
    public String getHost()
    {
        return host;
    }

}
