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

import javax.security.auth.x500.X500Principal;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractX509CredentialsMatcher
        implements CredentialsMatcher
{

    protected static final Logger LOGGER = LoggerFactory.getLogger( AbstractX509CredentialsMatcher.class );

    @Override
    public final boolean doCredentialsMatch( AuthenticationToken token, AuthenticationInfo info )
    {
        return doX509CredentialsMatch( ( X509AuthenticationToken ) token, ( X509AuthenticationInfo ) info );
    }

    public abstract boolean doX509CredentialsMatch( X509AuthenticationToken token, X509AuthenticationInfo info );

    protected final String toString( X500Principal dn )
    {
        return dn.getName( X500Principal.CANONICAL );
    }

    protected final boolean doEquals( X500Principal one, X500Principal other )
    {
        return toString( one ).equals( toString( other ) );
    }

}
