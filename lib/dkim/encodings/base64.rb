module Dkim
  module Encodings
    class Base64
      def decode data
        data.gsub(/\s/, '').unpack('m')[0]
      end
      def encode data
        return nil if data.nil?()
        [data].pack('m0').gsub("\n", '')
      end
    end
  end
end
