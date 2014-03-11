module Dkim
  module Encodings
    module PipeSeparated
      PIPE = '|'.freeze
      
      def encode(v)
        super(v.to_s().join(PIPE))
      end
      
      def decode(v)
        super(v).to_s().split(PIPE)
      end
    end
  end
end