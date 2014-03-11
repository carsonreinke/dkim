module Dkim
  module Encodings
    module SlashSeparated
      SLASH = '/'.freeze
      
      def encode(v)
        super(v.to_s().join(SLASH))
      end
      
      def decode(v)
        super(v).to_s().split(SLASH)
      end
    end
  end
end
