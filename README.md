# Bare bones http digest for Android

This project is a partial implementation of the [HTTP
Digest](https://en.wikipedia.org/wiki/Digest_access_authentication)
authentication scheme for Android. With a small effort you can use it
to get HTTP digest working with `HttpURLConnection` or any other HTTP
stack.

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

If you only need basic HTTP digest functionality the approaches above
may be overkill. This library can help you implement HTTP digest on
top of `HttpURLConnection` (or some other HTTP stack) without too much
trouble.

## How?

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

To implement HTTP digest with this library, do the following:

- Make a request to the server.
- Check the response, if the status code is 401 examine the
  headers. For each `WWW-Authenticate header` (there can be more than
  one), pass the value to `DigestChallenge.parse()`. If it returns
  non-`null`, the header contains a HTTP Digest challenge.
- Generate a response using `DigestChallengeResponse.responseTo`. Add
  the credentials (by calling `username` and `password`) and fill in
  details about the request (`uri` and `requestMethod`).
- Make the request again, this time with an added `Authorization`
  header. Obtain the value from
  `DigestChallengeResponse.getHeaderValue`.
- Done. Optionally save the `DigestChallengeResponse` instance and use
  it to generate `Authorization` headers for future request. Before
  each use, call `incrementNonceCount` to increment a counter in the
  header or the server will reject the request.
