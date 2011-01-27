
Apache Shiro Extensions
=======================

This project contains [Apache Shiro](http://shiro.apache.org/ "Apache Shiro") extensions.

    "Apache Shiro is a powerful and easy-to-use Java security framework that performs
     authentication, authorization, cryptography, and session management. With Shiro’s
     easy-to-understand API, you can quickly and easily secure any application – from
     the smallest mobile applications to the largest web and enterprise applications."

For now only x509 related extensions are available.


X509
----

This extension is splitted in two jars :

- shiro-ext-x509-core that depends on [slf4j-api](http://www.slf4j.org/), [bouncycastle](http://www.bouncycastle.org/) provider and shiro-c
ore,
- shiro-ext-x509-web that depends on shiro-ext-x509-core and shiro-web.

You certainly want to depend on the -web artifact.

Be sure to read about X509 certificates before choosing an authentication strategy.


### CredentialsMatchers

The following credential matchers are provided:

- X509CredentialsPKIXPathMatcher

    Custom PKIX path validation based on granted trust anchors provided by your Realm. Works for direct X509 authentication and with forwarded X509 authentication only if the full client certificate is available.

- X509CredentialsSha256Matcher

    Compute the Sha256 hashes of the client certificate and the one provided by your Realm and compare them. Works for direct X509 authentication and with forwarded X509 authentication only if the full client certificate is available.

- X509CredentialsIssuerDNSNMatcher

    Compare issuer distinguished name and serial number of the client certificate against info provided by your Realm. Works in both X509 authentication modes, usefull if your Realm can not access the full certificate.

- X509CredentialsSujbectDNMatcher

    Compare subject distinguished name of the client certificate against info provided by your Realm. Works in both X509 authentication modes, usefull if your Realm can not access the full certificate.



### Your X509 Realm

You will need to implement a Realm extending AbstractX509Realm and use it in your Shiro configuration:

    [main]
    x509Realm = com.acme.YourRealm



### Client X509Certificate authentication

Use the following filter in your Shiro configuration:

    [main]
    x509 = org.codeartisans.shiro.x509.web.filter.authc.X509AuthenticationFilter

    [urls]
    /protected = x509



### Forwarded X509 authentication

You need this if your application is deployed in a container siting behind a reverse proxy and hence the ssl handshake is done by the reverse proxy.

For now the HTTP headers used to read forwarded SSL data from reverse proxies use the following names:

- X-SSL-Client-Cert
- X-SSL-Client-S-DN
- X-SSL-Client-I-DN
- X-SSL-Client-M-Serial

If you need configuration support for the header names, please fill an issue.

By default the filter read __no__ headers and hence simply refuse any authentication attempt.
You need to choose which headers to use in order to build the X509AuthenticationToken that will be used by the CredentialMatcher of your choice.

Here are three Shiro configuration snippets for the different CredentialMatchers:

For X509CredentialsPKIXPathMatcher or X509CredentialsSha256Matcher:

    [main]
    x509 = org.codeartisans.shiro.x509.web.filter.authc.ForwardedX509AuthenticationFilter
    x509.useCertificate = true

    [urls]
    /protected = x509


For X509CredentialsIssuerDNSNMatcher:

    [main]
    x509 = org.codeartisans.shiro.x509.web.filter.authc.ForwardedX509AuthenticationFilter
    x509.useIssuerDN = true
    x509.useSerialNumber = true

    [urls]
    /protected = x509


For X509CredentialsSujbectDNMatcher:

    [main]
    x509 = org.codeartisans.shiro.x509.web.filter.authc.ForwardedX509AuthenticationFilter
    x509.useSubjectDN = true

    [urls]
    /protected = x509

