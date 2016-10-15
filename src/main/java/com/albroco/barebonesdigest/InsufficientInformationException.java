// Copyright (c) 2016 Petter Wintzell

package com.albroco.barebonesdigest;

/**
 * Indicates that not enough information has been provided to perform the requested operation.
 */
public class InsufficientInformationException extends IllegalStateException {
  /**
   * Constructs a new {@code InsufficientInformationException} with its stack trace and detail
   * message filled in.
   *
   * @param detailMessage the detail message for this exception.
   */
  public InsufficientInformationException(String detailMessage) {
    super(detailMessage);
  }

  /**
   * Constructs a new instance of this class with detail message and cause filled in.
   *
   * @param message The detail message for the exception.
   * @param cause   The detail cause for the exception.
   */
  public InsufficientInformationException(String message, Throwable cause) {
    super(message, cause);
  }

  /**
   * Constructs a new instance of this class with its detail cause filled in.
   *
   * @param cause The detail cause for the exception.
   */
  public InsufficientInformationException(Throwable cause) {
    super(cause);
  }
}
