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
package org.codeartisans.shiro.realm.x509;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.realm.AuthorizingRealm;

import org.codeartisans.shiro.authc.x509.X509AuthenticationInfo;
import org.codeartisans.shiro.authc.x509.X509AuthenticationToken;

public abstract class AbstractX509Realm
        extends AuthorizingRealm
{

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo( AuthenticationToken token )
            throws AuthenticationException
    {
        return doGetX509AuthenticationInfo( (X509AuthenticationToken) token );
    }

    protected abstract X509AuthenticationInfo doGetX509AuthenticationInfo( X509AuthenticationToken x509AuthenticationToken );

}
