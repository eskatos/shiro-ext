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
package org.codeartisans.shiro.web.filter.authc;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.ShiroException;
import org.apache.shiro.authc.AuthenticationToken;

import org.apache.shiro.web.filter.authc.AuthenticatingFilter;

import org.codeartisans.shiro.authc.x509.X509AuthenticationToken;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class X509AuthenticationFilter
        extends AuthenticatingFilter
{

    private static final Logger LOGGER = LoggerFactory.getLogger( X509AuthenticationFilter.class );

    @Override
    protected boolean onAccessDenied( ServletRequest request, ServletResponse response )
            throws Exception
    {
        return executeLogin( request, response );
    }

    @Override
    protected AuthenticationToken createToken( ServletRequest request, ServletResponse response )
    {
        X509Certificate[] clientCertChain = ( X509Certificate[] ) request.getAttribute( "javax.servlet.request.X509Certificate" );
        if( LOGGER.isDebugEnabled() )
        {
            LOGGER.debug( "X509AuthFilter.createToken() cert chain is {}", Arrays.toString( clientCertChain ) );
        }
        if ( clientCertChain == null || clientCertChain.length < 1 ) {
            throw new ShiroException( "Request do not contain any X509Certificate" );
        }
        return new X509AuthenticationToken( clientCertChain, getHost( request ) );
    }

}
