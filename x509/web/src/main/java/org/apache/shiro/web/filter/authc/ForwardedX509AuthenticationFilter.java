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
package org.apache.shiro.web.filter.authc;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.x509.X509AuthenticationToken;
import org.apache.shiro.codec.Hex;
import org.apache.shiro.codec.Base64;

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

    private static final Logger LOGGER = LoggerFactory.getLogger( ForwardedX509AuthenticationFilter.class );
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

            X509Certificate[] certificateChain = null;

            String certHeader = httpRequest.getHeader( SSL_CLIENT_CERT );
            if ( notEmpty( certHeader ) ) {
                certificateChain = readX509CertificateChainFromPEM( rebuildPEMBundleFromHttpHeader( certHeader ) );
            }

            if ( certificateChain == null ) {
                throw new AuthenticationException( "Set up to use " + SSL_CLIENT_CERT + " header but it was either empty or unparseable" );
            }

            return new X509AuthenticationToken( certificateChain, getHost( request ) );

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

    private static final String PEM_BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
    private static final String PEM_END_CERT = "-----END CERTIFICATE-----";
    private static final String TEMP_BEGIN_CERT = "-----BEGIN_CERTIFICATE-----";
    private static final String TEMP_END_CERT = "-----END_CERTIFICATE-----";

    private String rebuildPEMBundleFromHttpHeader( String httpHeaderValue )
    {
        httpHeaderValue = httpHeaderValue.replaceAll( PEM_BEGIN_CERT, TEMP_BEGIN_CERT );
        httpHeaderValue = httpHeaderValue.replaceAll( PEM_END_CERT, TEMP_END_CERT );
        httpHeaderValue = httpHeaderValue.replaceAll( "\\s", "\n" );
        httpHeaderValue = httpHeaderValue.replaceAll( TEMP_BEGIN_CERT, PEM_BEGIN_CERT );
        httpHeaderValue = httpHeaderValue.replaceAll( TEMP_END_CERT, PEM_END_CERT );
        return httpHeaderValue;
    }

    private X509Certificate[] readX509CertificateChainFromPEM( String pem )
    {
        try {
            List<X509Certificate> pemBundle = loadPEMBundle( new StringReader( pem ) );
            if ( pemBundle.isEmpty() ) {
                return null;
            }
            return pemBundle.toArray( new X509Certificate[ pemBundle.size() ] );
        } catch ( CertificateException ex ) {
            LOGGER.warn( "Unparseable PEM X509Certificate, will use null and continue. Here is the PEM:\n{}", pem, ex );
            return null;
        } catch ( IOException ex ) {
            LOGGER.warn( "Unparseable PEM X509Certificate, will use null and continue. Here is the PEM:\n{}", pem, ex );
            return null;
        }
    }

    private static final String PEM_BEGIN = "-----BEGIN";
    private static final String PEM_END = "-----END";

    private static List<X509Certificate> loadPEMBundle( final Reader pemBundleReader )
            throws IOException, CertificateException
    {
        BufferedReader br = null;
        final String malformed = "Malformed PEM X.509 Certificate Bundle";
        try {
            br = new BufferedReader( pemBundleReader );
            String line = br.readLine();
            if ( !line.startsWith( PEM_BEGIN ) ) {
                throw new CertificateException( malformed );
            }
            final List<X509Certificate> certList = new ArrayList<X509Certificate>();
            boolean begin = false;
            boolean end = true;
            StringBuilder x509Base64 = new StringBuilder();
            CertificateFactory certFactory = CertificateFactory.getInstance( "X.509" );
            while ( line != null ) {
                if ( line.length() > 0 ) {
                    if ( line.startsWith( PEM_BEGIN ) ) {
                        if ( !begin && end ) {
                            begin = true;
                            end = false;
                            x509Base64 = new StringBuilder();
                        } else {
                            throw new CertificateException( malformed );
                        }
                    } else if ( line.startsWith( PEM_END ) ) {
                        if ( begin || !end ) {
                            begin = false;
                            end = true;
                            byte[] base64DecodedCert = Base64.decode( x509Base64.toString() );
                            certList.add( ( X509Certificate ) certFactory.generateCertificate( new ByteArrayInputStream( base64DecodedCert ) ) );
                        } else {
                            throw new CertificateException( malformed );
                        }
                    } else if ( begin && !end ) {
                        x509Base64.append( line );
                    }
                }
                line = br.readLine();
            }
            if ( begin || !end ) {
                throw new CertificateException( malformed );
            }
            return certList;
        } finally {
            if ( br != null ) {
                try {
                    br.close();
                } catch ( IOException ignored ) {
                }
            }
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
