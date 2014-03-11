require 'dkim/verify/errors/failure_error'

module Dkim
  module Verify
    #PERMFAIL: a permanent, non-recoverable error such as a signature verification failure
    class PermanentFailureError < FailureError
      def initialize(message = nil)
        super(message || 'Permanent Failure')
      end
    end
    
    #PERMFAIL (signature syntax error)
    class SignatureSyntaxError < PermanentFailureError; end
    #PERMFAIL (incompatible version)
    class IncompatibleVersionError < PermanentFailureError; end
    #PERMFAIL (signature missing required tag)
    class SignatureMissingRequiredTagError < PermanentFailureError; end
    #PERMFAIL (domain mismatch)
    class DomainMismatchError < PermanentFailureError; end
    #PERMFAIL (From field not signed)
    class FromFieldNotSignedError < PermanentFailureError; end
    #PERMFAIL (signature expired)
    class SignatureExpiredError < PermanentFailureError; end
    #PERMFAIL (unacceptable signature header)
    class UnacceptableSignatureHeaderError < PermanentFailureError; end
    #PERMFAIL (no key for signature)
    class NoKeyForSignatureError < PermanentFailureError; end
    #PERMFAIL (key syntax error)
    class KeySyntaxError < PermanentFailureError; end
    #PERMFAIL (inappropriate hash algorithm)
    class InappropriateHashAlgorithmError < PermanentFailureError; end
    #PERMFAIL (key revoked)
    class KeyRevokedError < PermanentFailureError; end
    #PERMFAIL (inappropriate key algorithm)
    class InappropriateKeyAlgorithmError < PermanentFailureError; end
    #PERMFAIL (body hash did not verify)
    class BodyHashDidNotVerifyError < PermanentFailureError; end
    #PERMFAIL (signature did not verify)
    class SignatureDidNotVerifyError < PermanentFailureError; end
    #PERMFAIL (unsigned content)
    class UnsignedContentError < PermanentFailureError; end
  end
end