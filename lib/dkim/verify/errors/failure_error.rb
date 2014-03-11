require 'dkim/verify/errors/error'

module Dkim
  module Verify
    class FailureError < Error
      def initialize(message = nil)
        super(message || 'Unknown Failure')
      end
    end
  end
end