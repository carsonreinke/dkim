module Dkim
  module Encodings
    module ColonSeparated
      COLON = ':'.freeze
      
      def encode(v)
        super(v.to_s().join(COLON))
      end
      
      def decode(v)
        super(v).to_s().split(COLON)
      end
    end
  end
end
