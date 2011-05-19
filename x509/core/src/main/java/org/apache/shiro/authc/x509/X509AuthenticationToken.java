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

import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import javax.security.auth.x500.X500Principal;

import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.HostAuthenticationToken;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.NoSuchStoreException;
import org.bouncycastle.x509.X509CertStoreSelector;
import org.bouncycastle.x509.X509CollectionStoreParameters;
import org.bouncycastle.x509.X509Store;

public class X509AuthenticationToken
        implements AuthenticationToken, HostAuthenticationToken
{

    private static final long serialVersionUID = 1L;
    private final X509Certificate certificate;
    private final X509Certificate[] certChain;
    private final X500Principal subjectDN;
    private final X500Principal issuerDN;
    private final String hexSerialNumber;
    private final String host;

    public X509AuthenticationToken( X509Certificate[] clientCertChain, String host )
    {
        if ( clientCertChain == null || clientCertChain.length < 1 ) {
            throw new IllegalArgumentException( "No certificate in the chain" );
        }
        this.certChain = clientCertChain;
        this.certificate = this.certChain[0];
        this.subjectDN = certificate.getSubjectX500Principal();
        this.issuerDN = certificate.getIssuerX500Principal();
        this.hexSerialNumber = certificate.getSerialNumber().toString( 16 );
        this.host = host;
    }

    public X509AuthenticationToken( X500Principal clientSubjectDN, X500Principal clientIssuerDN, String clientHexSerialNumber, String host )
    {
        this.certificate = null;
        this.certChain = new X509Certificate[]{};
        this.subjectDN = clientSubjectDN;
        this.issuerDN = clientIssuerDN;
        this.hexSerialNumber = clientHexSerialNumber;
        this.host = host;
    }

    public X509Certificate getX509Certificate()
    {
        return certificate;
    }

    public X509CertStoreSelector getX509CertSelector()
    {
        X509CertStoreSelector certSelector = new X509CertStoreSelector();
        certSelector.setCertificate( certificate );
        return certSelector;
    }

    public X509Store getX509CertChainStore()
    {
        try {
            X509CollectionStoreParameters params = new X509CollectionStoreParameters( Arrays.asList( certChain ) );
            return X509Store.getInstance( "CERTIFICATE/COLLECTION", params, BouncyCastleProvider.PROVIDER_NAME );
        } catch ( NoSuchStoreException ex ) {
            return null;
        } catch ( NoSuchProviderException ex ) {
            return null;
        }
    }

    public X500Principal getSubjectDN()
    {
        return subjectDN;
    }

    public X500Principal getIssuerDN()
    {
        return issuerDN;
    }

    public String getHexSerialNumber()
    {
        return hexSerialNumber;
    }

    @Override
    public Object getPrincipal()
    {
        return subjectDN;
    }

    @Override
    public Object getCredentials()
    {
        return null;
    }

    @Override
    public String getHost()
    {
        return host;
    }

}
