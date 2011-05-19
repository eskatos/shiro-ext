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
import org.apache.shiro.codec.Hex;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;

import org.bouncycastle.openssl.PEMReader;

import org.codeartisans.shiro.x509.ShiroExtX509;
import org.codeartisans.shiro.x509.core.authc.X509AuthenticationToken;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * AuthenticatingFilter for forwarded X509 authentication.
 *
 * This AuthenticatingFilter create an AuthenticationToken containing all available http
 * headers containing information about a forwarded X509 authentication.
 *
 * As there is no standard for http header names used to forward X509 authentication,
 * this filter assume that used format is X-SSL-Client-*.
 *
 * This is the Realm and CredentialMatcher responsibility to choose which headers to handle.
 */
public class ForwardedX509AuthenticationFilter
        extends AuthenticatingFilter
{

    private static final Logger LOGGER = LoggerFactory.getLogger( ShiroExtX509.LOGGER_NAME );
    private static final String SSL_CLIENT_VERIFY = "X-SSL-Client-Verify";
    private static final String SSL_CLIENT_CERT = "X-SSL-Client-Cert";
    private static final String SSL_CLIENT_S_DN = "X-SSL-Client-S-DN";
    private static final String SSL_CLIENT_I_DN = "X-SSL-Client-I-DN";
    private static final String SSL_CLIENT_M_SERIAL = "X-SSL-Client-M-Serial";
    private boolean useCertificate = false;
    private boolean useSubjectDN = false;
    private boolean useIssuerDN = false;
    private boolean useSerialNumber = false;

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
        HttpServletRequest httpRequest = ( HttpServletRequest ) request;

        if ( !useCertificate && !useSubjectDN && !useIssuerDN && !useSerialNumber ) {
            throw new AuthenticationException( "ForwardedX509AuthenticationFilter is set up to use no forwarded header, you certainly missed a configuration step" );
        }

        if ( false ) {
            // FIXME Decide what to do with the -Verify header
            String verifiedHeader = httpRequest.getHeader( SSL_CLIENT_VERIFY );
            if ( !verifiedHeader.isEmpty() ) {
                if ( !"SUCCESS".equals( verifiedHeader ) ) {
                    throw new AuthenticationException( "Client certificate verification failure was forwarded" );
                }
            }
        }

        if ( useCertificate ) {

            X509Certificate certificate = null;

            String certHeader = httpRequest.getHeader( SSL_CLIENT_CERT );
            if ( notEmpty( certHeader ) ) {
                certificate = readX509CertificateFromPEM( certHeader );
            }

            if ( certificate == null ) {
                throw new AuthenticationException( "Set up to use " + SSL_CLIENT_CERT + " header but it was either empty or unparseable" );
            }

            return new X509AuthenticationToken( new X509Certificate[]{ certificate }, getHost( request ) );

        }

        X500Principal subjectDN = null;
        X500Principal issuerDN = null;
        String hexSerialNumber = null;

        if ( useSubjectDN ) {
            String subjectDNHeader = httpRequest.getHeader( SSL_CLIENT_S_DN );
            if ( notEmpty( subjectDNHeader ) ) {
                subjectDN = readX500PrincipalFromString( subjectDNHeader );
            }
        }

        if ( useIssuerDN ) {
            String issuerDNHeader = httpRequest.getHeader( SSL_CLIENT_I_DN );
            if ( notEmpty( issuerDNHeader ) ) {
                issuerDN = readX500PrincipalFromString( issuerDNHeader );
            }
        }

        if ( useSerialNumber ) {
            String serialHeader = httpRequest.getHeader( SSL_CLIENT_M_SERIAL );
            if ( notEmpty( serialHeader ) ) {
                hexSerialNumber = readHexSerialNumberFromString( serialHeader );
            }
        }

        if ( subjectDN == null && issuerDN == null && isEmpty( hexSerialNumber ) ) {
            throw new AuthenticationException( "All set up forwarded headers were empty" );
        }

        return new X509AuthenticationToken( subjectDN, issuerDN, hexSerialNumber, getHost( request ) );
    }

    private static boolean isEmpty( String str )
    {
        return !notEmpty( str );
    }

    private static boolean notEmpty( String str )
    {
        return str != null && str.length() > 1;
    }

    private X509Certificate readX509CertificateFromPEM( String pem )
    {
        try {
            return ( X509Certificate ) new PEMReader( new StringReader( pem ) ).readObject();
        } catch ( IOException ex ) {
            LOGGER.warn( "Unparseable PEM X509Certificate, will use null and continue. Here is the PEM:\n{}", pem, ex );
            return null;
        }
    }

    private X500Principal readX500PrincipalFromString( String dn )
    {
        try {
            return new X500Principal( dn );
        } catch ( IllegalArgumentException ex ) {
            LOGGER.warn( "Unparseable DN in header string, will use null and continue. Here is the header string: {}", dn, ex );
            return null;
        }
    }

    private String readHexSerialNumberFromString( String input )
    {
        return Hex.encodeToString( Hex.decode( input ) ); // FIXME Upstream Hex implementation is not char encoding safe, fix it there
    }

    public void setUseCertificate( boolean useCertificate )
    {
        this.useCertificate = useCertificate;
    }

    public void setUseIssuerDN( boolean useIssuerDN )
    {
        this.useIssuerDN = useIssuerDN;
    }

    public void setUseSerialNumber( boolean useSerialNumber )
    {
        this.useSerialNumber = useSerialNumber;
    }

    public void setUseSubjectDN( boolean useSubjectDN )
    {
        this.useSubjectDN = useSubjectDN;
    }

}
