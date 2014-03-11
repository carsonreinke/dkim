require 'dkim/dkim_header'
require 'dkim/tag_value_list'
require 'dkim/verify/resolver'
require 'dkim/encodings/slash_separated'
require 'dkim/encodings/colon_separated'
require 'dkim/encodings/pipe_separated'
require 'dkim/verify/errors/permanent_failure_errors'

module Dkim
  module Verify
    class Signature < DkimHeader
      #RFC 6376 Section 3.5
      DEFAULTS = {
        DkimHeader::CANONICALIZATION => 'simple/simple',
        DkimHeader::QUERY_METHODS => 'dns/txt'
      }.freeze()
      
      def initialize(header)
        self.key = DkimHeader::CAPITALIZED_FIELD
        @original = header
        @list = TagValueList.parse(header.value)
        DEFAULTS.each{ |k,v| @list[k] = v unless self.has_key?(k) }
        #RFC 6376 Section 3.5: default is an empty local-part followed by an "@" followed by the domain from the "d=" tag
        @list[DkimHeader::USER_IDENTIFIER] = "@#{self[DkimHeader::DOMAIN]}" unless self.has_key?(DkimHeader::USER_IDENTIFIER)
      end
      
      def has_key?(k)
        @list.keys.include?(k)
      end
      
      attr_reader :original
      
      #
      # Original DKIM-Signature without the actual signature
      #
      def original_without_signature()
        header = self.original.dup()
        list = TagValueList.parse(header.value)
        list[DkimHeader::SIGNATURE] = ''
        header.value = list.to_s()
        header
      end
      
      def policy()
        raise PermanentFailureError.new("Unsupported query method #{self[DkimHeader::QUERY_METHODS]}") unless self[DkimHeader::QUERY_METHODS].include?('dns/txt')
        @policy ||= Resolver.query(self[DkimHeader::DOMAIN], self[DkimHeader::SELECTOR])
      end
      
      def validate!()
        raise IncompatibleVersionError.new("Unsupported version #{self[DkimHeader::VERSION]}") unless self[DkimHeader::VERSION].to_i() == 1
        
        #Get alogorithm and policy, as these can raise errors
        self.algorithm()
        self.policy()
        
        raise SignatureMissingRequiredTagError.new('No signature') unless self.has_key?(DkimHeader::SIGNATURE)
        raise SignatureMissingRequiredTagError.new('No hash') unless self.has_key?(DkimHeader::HASH)
        raise SignatureMissingRequiredTagError.new('No headers') if self[DkimHeader::HEADERS].size() < 1
        
        #If the "h=" tag does not include the From header field, the Verifier
        #MUST ignore the DKIM-Signature header field and return PERMFAIL (From
        #field not signed).
        raise FromFieldNotSignedError.new('Missing From header in header tag') unless self[DkimHeader::HEADERS].include?('from')
      end
      
      def header_canonicalization()
        self[DkimHeader::CANONICALIZATION].first()
      end
      
      def body_canonicalization()
        #RFC 6376 Section 3.5: If only one algorithm is named, that algorithm is used for the header and "simple" is used for the body.
        self[DkimHeader::CANONICALIZATION][1] || 'simple' 
      end
      
      def algorithm()
        @algorithm ||= case self[DkimHeader::ALGORITHM]
        when 'rsa-sha1'
          OpenSSL::Digest::SHA1.new()
        when 'rsa-sha256'
          OpenSSL::Digest::SHA256.new()
        else
          raise NotImplementedError("Unsupported algorithm #{self[DkimHeader::ALGORITHM]}")
        end
      end
      
      def expired?(now = Time.now())
        #RFC 6376 Section 3.1: Signatures MAY be considered invalid if the 
        #verification time at the Verifier is past the expiration date.
        #The verification time should be the time that the message
        #was first received at the administrative domain of the Verifier if
        #that time is reliably available; otherwise, the current time
        #should be used.
        return false unless self.has_key?(DkimHeader::EXPIRATION)
        expiration = self[DkimHeader::EXPIRATION].to_i()
        return expiration <= now.to_i()
      end
      
      def is_domain_unacceptable?()
        #RFC 6376 Section 6.1.1: The list of unacceptable domains SHOULD be configurable.
        self.class.unacceptable_domains.include?(
          self[DkimHeader::DOMAIN].downcase()
        )
      end
      
      def user_identifier_local()
        user_identifier_parts[0]
      end
      def user_identifier_domain()
        user_identifier_parts[1]
      end
      
      def is_user_identifier_domain_valid?()
        #RFC 6376 Section 3.1: The domain part of the address MUST be the same as, or a subdomain of, the value of the "d=" tag.
        self.user_identifier_domain.casecmp(self[DkimHeader::DOMAIN]) == 0 ||
        (
          #RFC 6376 Section 3.6: That is, the "i=" domain MUST NOT be a subdomain of "d="
          !self.policy.require_exact_user_identifier_domain?() &&
          self.user_identifier_domain.downcase().end_with?(".#{self[DkimHeader::DOMAIN.downcase]}")
        )
      end
      
      
    protected
      def encoder_for(key)
        encoder = super(key)
        case key
        when DkimHeader::CANONICALIZATION
          encoder.extend(Encodings::SlashSeparated)
        when DkimHeader::HEADERS, DkimHeader::QUERY_METHODS
          encoder.extend(Encodings::ColonSeparated)
        when DkimHeader::COPIED_HEADERS
          encoder.extend(Encodings::PipeSeparated)
        else
          encoder
        end
      end
      
      
    private
      def user_identifier_parts()
        return @user_identifier_parts if defined?(@user_identifier_parts)
        
        #TODO There has to be a better way to do this :(
        @user_identifier_parts = self[DkimHeader::USER_IDENTIFIER].split('@', 2)
        @user_identifier_parts.unshift(*(
          [nil] * 2 - @user_identifier_parts.size()
        )) if @user_identifier_parts.size() < 2
        @user_identifier_parts.map!{|i| i.empty?() ? nil : i}
        
        @user_identifier_parts
      end
      
      
      class << self
        
        def unacceptable_domains()
          @unacceptable_domains ||= []
        end
        def unacceptable_domains=(v)
          @unacceptable_domains = v.map(&:downcase)
        end
        
        
        def find_all(headers = [])
          headers.find_all do |header|
            header.key.casecmp(DkimHeader::CAPITALIZED_FIELD) == 0
          end.map do |header|
            self.new(header)
          end
        end
      end
    end
  end
end