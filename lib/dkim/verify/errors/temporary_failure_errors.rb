require 'dkim/verify/errors/failure_error'

module Dkim
  module Verify
    #TEMPFAIL: a temporary, recoverable error such as a DNS query timeout
    class TemporaryFailureError < FailureError
      def initialize(message = nil)
        super(message || 'Temporary Failure')
      end
    end
    
    #TEMPFAIL (key unavailable)
    class KeyUnavailableError < TemporaryFailureError; end
  end
end