package com.albroco.barebonesdigest;

/**
 * Indicates that a HTTP digest challenge could not be parsed because it is malformed.
 */
public class ChallengeParseHttpDigestException extends HttpDigestException {
  /**
   * Constructs a new {@code ChallengeParseHttpDigestException} with its stack trace and detail
   * message filled in.
   *
   * @param detailMessage the detail message for this exception.
   */
  public ChallengeParseHttpDigestException(String detailMessage) {
    super(detailMessage);
  }

  /**
   * Constructs a new instance of this class with detail message and cause filled in.
   *
   * @param message The detail message for the exception.
   * @param cause   The detail cause for the exception.
   */
  public ChallengeParseHttpDigestException(String message, Throwable cause) {
    super(message, cause);
  }

  /**
   * Constructs a new instance of this class with its detail cause filled in.
   *
   * @param cause The detail cause for the exception.
   */
  public ChallengeParseHttpDigestException(Throwable cause) {
    super(cause);
  }
}
