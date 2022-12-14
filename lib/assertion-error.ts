import { CustomError, Status } from '@block65/custom-error';

interface AssertionErrorParams {
  message: string;
  actual: unknown;
  expected: unknown;
}

export class AssertionError extends CustomError {
  public expected: unknown;

  public actual: unknown;

  public constructor(params: AssertionErrorParams, err?: Error);
  public constructor(message: string, err?: Error);
  public constructor(
    messageOrParams: string | AssertionErrorParams,
    err?: Error,
  ) {
    if (typeof messageOrParams === 'string') {
      super(messageOrParams, err);
    } else {
      super(messageOrParams.message, err);
      this.expected = messageOrParams.expected;
      this.actual = messageOrParams.actual;
    }

    // this.setName('AssertionError');
    this.code = Status.FAILED_PRECONDITION;
  }
}
