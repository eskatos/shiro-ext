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

import java.io.IOException;
import java.io.StringWriter;
import java.security.cert.X509Certificate;

import org.apache.shiro.crypto.CryptoException;

import org.bouncycastle.openssl.PEMWriter;

import org.joda.time.DateTime;

public class DefaultX509
        extends DefaultX509Light
        implements X509
{

    public DefaultX509( X509Certificate x509 )
    {
        super( x509 );
    }

    @Override
    public final DateTime issuanceDateTime()
    {
        return new DateTime( x509.getNotBefore() );
    }

    @Override
    public final DateTime expirationDateTime()
    {
        return new DateTime( x509.getNotAfter() );
    }

    @Override
    public final String pem()
    {
        try {
            StringWriter out = new StringWriter();
            PEMWriter pemWriter = new PEMWriter( out );
            pemWriter.writeObject( x509 );
            pemWriter.flush();
            return out.toString();
        } catch ( IOException ex ) {
            throw new CryptoException( "Unable to build PEM from X509Certificate", ex );
        }
    }

    @Override
    public final X509Certificate x509Certificate()
    {
        return x509;
    }

}
