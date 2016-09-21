package com.albroco.barebonesdigest;

/**
 * Indicates that no response can be generated to a challenge since the challenge uses an
 * unsupported algorithm.
 */
public class UnsupportedHttpDigestAlgorithmException extends HttpDigestException {
  /**
   * Constructs a new {@code UnsupportedHttpDigestAlgorithmException} with its stack trace and
   * detail message filled in.
   *
   * @param detailMessage the detail message for this exception.
   */
  public UnsupportedHttpDigestAlgorithmException(String detailMessage) {
    super(detailMessage);
  }

  /**
   * Constructs a new instance of this class with detail message and cause filled in.
   *
   * @param message The detail message for the exception.
   * @param cause   The detail cause for the exception.
   */
  public UnsupportedHttpDigestAlgorithmException(String message, Throwable cause) {
    super(message, cause);
  }

  /**
   * Constructs a new instance of this class with its detail cause filled in.
   *
   * @param cause The detail cause for the exception.
   */
  public UnsupportedHttpDigestAlgorithmException(Throwable cause) {
    super(cause);
  }
}
