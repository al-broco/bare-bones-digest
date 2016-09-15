package org.barebonesdigest;

import java.io.IOException;

/**
 * Indicates an HTTP digest related error.
 */
public class HttpDigestException extends IOException {

  /**
   * Constructs a new {@code HttpDigestException} with its stack trace and detail message filled in.
   *
   * @param detailMessage the detail message for this exception.
   */
  public HttpDigestException(String detailMessage) {
    super(detailMessage);
  }

  /**
   * Constructs a new instance of this class with detail message and cause filled in.
   *
   * @param message The detail message for the exception.
   * @param cause   The detail cause for the exception.
   */
  public HttpDigestException(String message, Throwable cause) {
    super(message, cause);
  }

  /**
   * Constructs a new instance of this class with its detail cause filled in.
   *
   * @param cause The detail cause for the exception.
   */
  public HttpDigestException(Throwable cause) {
    super(cause);
  }
}
