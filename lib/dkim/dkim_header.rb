
require 'dkim/header'
require 'dkim/tag_value_list'
require 'dkim/encodings'

module Dkim
  class DkimHeader < Header
    CAPITALIZED_FIELD = 'DKIM-Signature'.freeze
    
    VERSION = 'v'.freeze
    DOMAIN = 'd'.freeze
    SELECTOR = 's'.freeze
    ALGORITHM = 'a'.freeze
    SIGNATURE = 'b'.freeze
    HASH = 'bh'.freeze
    CANONICALIZATION = 'c'.freeze
    HEADERS = 'h'.freeze
    USER_IDENTIFIER = 'i'.freeze
    BODY_LENGTH = 'l'.freeze
    QUERY_METHODS = 'q'.freeze
    TIMESTAMP = 't'.freeze
    EXPIRATION = 'x'.freeze
    COPIED_HEADERS = 'z'.freeze
    
    attr_reader :list
    def initialize values={}
      self.key = CAPITALIZED_FIELD
      @list = TagValueList.new values
    end
    def value
      " #{@list}"
    end
    def [] k
      encoder_for(k).decode(@list[k])
    end
    def []= k, v
      @list[k] = encoder_for(k).encode(v)
    end

    protected
    def encoder_for key
      case key
      when VERSION, ALGORITHM, CANONICALIZATION, DOMAIN, HEADERS, BODY_LENGTH, QUERY_METHODS, SELECTOR, TIMESTAMP, EXPIRATION
        Encodings::PlainText
      when USER_IDENTIFIER, COPIED_HEADERS
        Encodings::DkimQuotedPrintable
      when SIGNATURE, HASH
        Encodings::Base64
      else
        raise "unknown key: #{key}"
      end.new
    end
  end
end
