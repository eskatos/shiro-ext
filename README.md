
Apache Shiro Extensions
=======================

X509
----

This extension is splitted in two jars :

- shiro-ext-x509-core
- shiro-ext-x509-web

You certainly want to depend on the -web artifact.

Be sure to read about X509 certificates before choosing an authentication strategy.


### CredentialsMatchers

The following credential matchers are provided:

- X509CredentialsPKIXPathMatcher
- X509CredentialsSha256Matcher
- X509CredentialsIssuerDNSNMatcher
- X509CredentialsSujbectDNMatcher



### Your X509 Realm

You will need to implement a Realm extending AbstractX509Realm and use it:

    [main]
    x509Realm = com.acme.YourRealm



### Client X509Certificate authentication

Use the following filter in your configuration:

    [main]
    x509 = org.codeartisans.shiro.x509.web.filter.authc.X509AuthenticationFilter

    [urls]
    /protected = x509



### Forwarded X509 authentication

You need this if your application is deployed in a container siting behind a reverse proxy.

For now the HTTP headers used to read forwarded SSL data from reverse proxies use the following names:

- X-SSL-Client-Cert
- X-SSL-Client-S-DN
- X-SSL-Client-I-DN
- X-SSL-Client-M-Serial

If you need configuration support for the header names, please fill an issue.

By default the filter read __no__ headers and hence simply refuse any authentication attempt.
You need to choose which headers to use in order to build the X509AuthenticationToken that will be used by the CredentialMatcher of your choice.

Here are the three configuration examples and the CredentialMatcher to use with:

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

