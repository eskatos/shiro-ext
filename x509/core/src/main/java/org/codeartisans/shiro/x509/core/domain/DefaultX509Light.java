/*
 * Created on 11 janv. 2011
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
package org.codeartisans.shiro.x509.core.domain;

import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;

import org.apache.shiro.codec.Hex;

public class DefaultX509Light
        implements X509Light
{

    protected final X509Certificate x509;

    public DefaultX509Light( X509Certificate x509 )
    {
        this.x509 = x509;
    }

    @Override
    public final String canonicalSubjectDN()
    {
        return x509.getSubjectX500Principal().getName( X500Principal.CANONICAL );
    }

    @Override
    public final String hexSerialNumber()
    {
        return Hex.encodeToString( x509.getSerialNumber().toByteArray() );
    }

    @Override
    public final String canonicalIssuerDN()
    {
        return x509.getIssuerX500Principal().getName( X500Principal.CANONICAL );
    }

}
