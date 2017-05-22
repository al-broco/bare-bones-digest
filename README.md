[![Build Status](https://travis-ci.org/al-broco/bare-bones-digest.svg?branch=master)](https://travis-ci.org/al-broco/bare-bones-digest)
[![codecov](https://codecov.io/gh/al-broco/bare-bones-digest/branch/master/graph/badge.svg)](https://codecov.io/gh/al-broco/bare-bones-digest)

# bare-bones-digest, HTTP digest authentication for Android

bare-bones-digest is an implementation of the [HTTP
Digest](https://en.wikipedia.org/wiki/Digest_access_authentication)
authentication scheme for Android. With a small effort you can use it
to get HTTP digest working with `HttpURLConnection` or any other HTTP
stack.

bare-bones-digest aims to support all features of HTTP digest that is
used in real-life applications. The goal is to be interoperable with
any server with a HTTP digest implementation.

As of version 1.0.0, bare-bones-digest is stable. Changes will only be
made as results of bug reports or feature requests.

## Why?

Android's standard class for HTTP communication,
[HttpURLConnection](https://developer.android.com/reference/java/net/HttpURLConnection.html),
has no built-in support for HTTP Digest. If you need HTTP digest
anyway here are some possible approaches:

* Use the Apache
  [HttpClient](https://developer.android.com/reference/org/apache/http/client/HttpClient.html)
  that is (or at least was) included in Android and that supports HTTP
  digest. Apache HttpClient has been included in Android from the very
  start, but Google recommends against using it unless you are
  targeting very old versions of Android (Froyo and older). The
  version of HttpClient included in Android is old and Google is not
  actively working on it and they have not been for some time. In API
  23 the [client was removed
  altogether](https://developer.android.com/sdk/api_diff/23/changes.html).
  Read [this blog post on the Android Developers
  blog](http://android-developers.blogspot.se/2011/09/androids-http-clients.html)
  for Google's stance.
* Use a newer version of Apache HttpClient. Note however that [Apache
  has discontinued the HttpClient for Android
  project](https://hc.apache.org/httpcomponents-client-4.5.x/android-port.html).
* Use [OkHttp](https://square.github.io/okhttp/) for HTTP requests. At
  the moment of this writing OkHttp does not natively support HTTP
  digest, but you can use a third-party authenticator such as
  [okhttp-digest](https://github.com/rburgst/okhttp-digest).

If none of the approaches above suit your needs you can use this
library to implement HTTP digest on top of `HttpURLConnection` (or
some other HTTP stack) without too much trouble.

## How?

bare-bones-digest is available from jcenter, include it as a dependency in
your project's `build.gradle`:

    dependencies {
        compile 'com.albroco:bare-bones-digest:1.0.0'
    }

Versioning follows [semver](http://semver.org).

### Digest Authentication at a glance

HTTP Digest is defined in [RFC
2617](https://tools.ietf.org/html/rfc2617). Wikipedia has [a good
explanation](https://en.wikipedia.org/wiki/Digest_access_authentication),
especially the example is good for a quick overview. The basics are as
follows:

- The client makes a HTTP request to the server.
- The server responds with status code 401, Unauthorized, and a
  challenge in a `WWW-Authenticate` HTTP header.
- The client sends the request again, now with an added `Authorization`
  HTTP header with a response to the challenge. The response contains
  a hash including the user's credentials, information about the
  request, and parts of the challenge.
- To avoid sending each request twice, in subsequent requests the
  client can reuse the challenge. Only the first request will have to
  be sent twice.

### Implementing HTTP Digest authentication

Here is an example of how to make a request and respond to a Digest
challenge:
```
// Step 1. Create the connection
URL url = new URL("http://httpbin.org/digest-auth/auth/user/passwd");
HttpURLConnection connection = (HttpURLConnection) url.openConnection();

// Step 2. Make the request and check to see if the response contains an authorization challenge
if (connection.getResponseCode() == HttpURLConnection.HTTP_UNAUTHORIZED) {
    // Step 3. Create a authentication object from the challenge...
    DigestAuthentication auth = DigestAuthentication.fromResponse(connection);
    // ...with correct credentials
    auth.username("user").password("passwd");

    // Step 4 (Optional). Check if the challenge was a digest challenge of a supported type
    if (!auth.canRespond()) {
        // No digest challenge or a challenge of an unsupported type - do something else or fail
        return;
    }

    // Step 5. Create a new connection, identical to the original one...
    connection = (HttpURLConnection) url.openConnection();
    // ...and set the Authorization header on the request, with the challenge response
    connection.setRequestProperty(DigestChallengeResponse.HTTP_HEADER_AUTHORIZATION,
        auth.getAuthorizationForRequest("GET", connection.getURL().getPath()));
}
```

[`DigestAuthentication`](http://al-broco.github.io/bare-bones-digest/javadoc/1.0.0/com/albroco/barebonesdigest/DigestAuthentication.html)
is the main entry point of the API, read the documentation for more examples. Some other useful
classes include:
* [`WwwAuthenticateHeader`](http://al-broco.github.io/bare-bones-digest/javadoc/1.0.0/com/albroco/barebonesdigest/WwwAuthenticateHeader.html)
  which can be used to parse challenges from `WWW-Authenticate` headers, including challenges of
  other types than Digest.
* [`DigestChallenge`](http://al-broco.github.io/bare-bones-digest/javadoc/1.0.0/com/albroco/barebonesdigest/DigestChallenge.html)
  which provides functionality for parsing digest challenges.
* [`DigestChallengeResponse`](http://al-broco.github.io/bare-bones-digest/javadoc/1.0.0/com/albroco/barebonesdigest/DigestChallengeResponse.html)
  which provides functionality for generating responses to digest challenges.

## Features

* Supports `MD5`, `MD5-sess`, `SHA-256`, and `SHA-256-sess`
  algorithms.
* Supports `auth`, `auth-int` and [RFC
  2069](https://tools.ietf.org/html/rfc2069) quality of protection.
* Somewhat lenient parsing, where common server mistakes (such as not
  quoting the `qop` directive) does not cause the parsing to fail.

## Interoperability

bare-bones-digest has been tested for interoperability with the
following servers:

* Apache HTTP Server v2.4 with
  [mod_auth_digest](http://httpd.apache.org/docs/2.4/mod/mod_auth_digest.html).
* [nodejs](https://nodejs.org) v4.2.6 with
  [Passport](http://passportjs.org/) v0.3.2 and
  [passport-http](https://github.com/jaredhanson/passport-http)
  v0.3.0.
* [nodejs](https://nodejs.org) v4.2.6 with
  [node-http-digest](https://github.com/thedjinn/node-http-digest)
  v0.1.0.
* An [Axis M1054](http://www.axis.com/se/sv/products/axis-m1054) camera.
* [httpbin](https://github.com/Runscope/httpbin) v0.5.

For each valid combination of qop and algorithm that the server
supports a single request has been successfully authenticated.

bare-bones-digest has been tested with, and is not compatible with,
the following servers:

* [nodejs](https://nodejs.org) v4.2.6 with
  [node-digest](https://github.com/wearefractal/node-digest) v0.0.5
  because of [this
  issue](https://github.com/wearefractal/node-digest/issues/2).

## Limitations

The implementation is based on [RFC
2617](https://tools.ietf.org/html/rfc2617). Features from [RFC
7616](https://tools.ietf.org/html/rfc7616) (which obsoletes RFC 2617)
are only partially implemented.

## Support

Please file a github issue if you have any problems! In particular,
file an issue if bare-bones-digest is not interoperable with your
server of choice.

## References

* [RFC 2069](https://tools.ietf.org/html/rfc2069) (obsolete): An
  Extension to HTTP : Digest Access Authentication.
* [RFC 2616](https://tools.ietf.org/html/rfc2616) (obsolete):
  Hypertext Transfer Protocol -- HTTP/1.1.
* [RFC 2617](https://tools.ietf.org/html/rfc2617) (obsolete): HTTP
  Authentication: Basic and Digest Access Authentication.
* [RFC 5234](https://tools.ietf.org/html/rfc5234): Augmented BNF for
  Syntax Specifications: ABNF.
* [RFC 7230](https://tools.ietf.org/html/rfc7230): Hypertext Transfer
  Protocol (HTTP/1.1): Message Syntax and Routing.
* [RFC 7235](https://tools.ietf.org/html/rfc7235): Hypertext Transfer
  Protocol (HTTP/1.1): Authentication.
* [RFC 7615](https://tools.ietf.org/html/rfc7615): HTTP
  Authentication-Info and Proxy-Authentication-Info Response Header
  Fields.
* [RFC 7616](https://tools.ietf.org/html/rfc7616): HTTP Digest Access
  Authentication.
* Wikipedia on [Digest access
  authentication](https://en.wikipedia.org/wiki/Digest_access_authentication).
* [draft-smith-sip-auth-examples-00.txt](http://www.cs.columbia.edu/sip/drafts/sip/draft-smith-sip-auth-examples-00.txt):
  Digest Authentication Examples for Session Initiation Protocol
  (SIP).
