/*
 * Copyright (c) 2010, Paul Merlin. All Rights Reserved.
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
package org.codeartisans.shiro.x509.web.filter.authc;

import java.io.IOException;
import java.io.StringReader;
import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;

import org.bouncycastle.openssl.PEMReader;

import org.codeartisans.shiro.x509.ShiroExtX509;
import org.codeartisans.shiro.x509.core.authc.X509ForwardedAuthenticationToken;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ForwardedX509AuthenticationFilter
        extends AuthenticatingFilter
{

    private static final Logger LOGGER = LoggerFactory.getLogger( ShiroExtX509.LOGGER_NAME );
    private static final String SSL_CLIENT_VERIFY = "X-SSL-Client-Verify";
    private static final String SSL_CLIENT_CERT = "X-SSL-Client-Cert";
    private static final String SSL_CLIENT_S_DN = "X-SSL-Client-S-DN";
    private static final String SSL_CLIENT_I_DN = "X-SSL-Client-I-DN";
    private static final String SSL_CLIENT_M_SERIAL = "X-SSL-Client-M-Serial";

    @Override
    protected boolean onAccessDenied( ServletRequest request, ServletResponse response )
            throws Exception
    {
        return executeLogin( request, response );
    }

    @Override
    protected AuthenticationToken createToken( ServletRequest request, ServletResponse response )
            throws Exception
    {
        X509Certificate certificate = null;
        X500Principal subjectDN = null;
        X500Principal issuerDN = null;
        String hexSerialNumber = null;

        HttpServletRequest httpRequest = ( HttpServletRequest ) request;

        String verifiedHeader = httpRequest.getHeader( SSL_CLIENT_VERIFY );
        if ( !verifiedHeader.isEmpty() ) {
            if ( !"SUCCESS".equals( verifiedHeader ) ) {
                throw new AuthenticationException( "Client certificate verification failure was forwarded, cannot continue" );
            }
        }

        String certHeader = httpRequest.getHeader( SSL_CLIENT_CERT );
        if ( !certHeader.isEmpty() ) {
            X509Certificate certCandidate = fromPem( certHeader );
            if ( certCandidate != null ) {
                certificate = certCandidate;
            }
        }

        String subjectDNHeader = httpRequest.getHeader( SSL_CLIENT_S_DN );
        if ( !subjectDNHeader.isEmpty() ) {
            subjectDN = fromDnString( subjectDNHeader );
        }

        String issuerDNHeader = httpRequest.getHeader( SSL_CLIENT_I_DN );
        if ( !issuerDNHeader.isEmpty() ) {
            issuerDN = fromDnString( issuerDNHeader );
        }

        String serialHeader = httpRequest.getHeader( SSL_CLIENT_M_SERIAL );
        if ( !serialHeader.isEmpty() ) {
            hexSerialNumber = serialHeader;
        }

        return new X509ForwardedAuthenticationToken( certificate, subjectDN, issuerDN, hexSerialNumber, getHost( request ) );

    }

    private X509Certificate fromPem( String pem )
    {
        try {
            return ( X509Certificate ) new PEMReader( new StringReader( pem ) ).readObject();
        } catch ( IOException ex ) {
            LOGGER.trace( "Unable to read X509Certificate from PEM, will use null and continue. Here is the PEM:\n{}", pem, ex );
            return null;
        }
    }

    private X500Principal fromDnString( String dn )
    {
        try {
            return new X500Principal( dn );
        } catch ( IllegalArgumentException ex ) {
            LOGGER.trace( "Unable to read DN from header string, will use null and continue. Here is the header string: {}", dn, ex );
            return null;
        }
    }

}
