require 'openssl'
require 'dkim/tag_value_list'
require 'dkim/encodings'
require 'dkim/encodings/colon_separated'
require 'dkim/verify/errors/permanent_failure_errors'
require 'dkim/verify/errors/temporary_failure_errors'

module Dkim
  module Verify
    class Policy
      VERSION = 'v'.freeze
      HASH_ALGORITHM = 'h'.freeze
      KEY_TYPE = 'k'.freeze
      NOTES = 'n'.freeze
      PUBLIC_KEY = 'p'.freeze
      SERVICE_TYPE = 's'.freeze
      FLAGS = 'f'.freeze
      
      #RFC 6376 Section 3.6
      DEFAULTS = {
        VERSION => 'DKIM1',
        HASH_ALGORITHM => 'sha1:sha256',
        KEY_TYPE => 'rsa',
        SERVICE_TYPE => '*'
      }.freeze
      
      def initialize(value)
        @list = TagValueList.parse(value)
        DEFAULTS.each{ |k,v| @list[k] = v unless self.has_key?(k) }
      end
      
      def [](k)
        encoder_for(k).decode(@list[k])
      end
      
      def []=(k, v)
        @list[k] = encoder_for(k).encode(v)
      end
      
      def has_key?(k)
        @list.keys.include?(k)
      end
      
      def validate!()
        raise KeySyntaxError.new("Missing public key #{PUBLIC_KEY}") unless self.has_key?(PUBLIC_KEY)
        
        #RFC 6376 Section 6.1.2.7: If the public-key data (the "p=" tag) is empty, then this key has
        #been revoked and the Verifier MUST treat this as a failed
        #signature check and return PERMFAIL (key revoked).  There is no
        #defined semantic difference between a key that has been revoked
        #and a key record that has been removed.
        raise KeyRevokedError.new() if self[PUBLIC_KEY].empty?()
        
        #No specific error for these
        raise NotImplementedError.new("Unsupported version #{self[VERSION]}") unless self[VERSION] == 'DKIM1'
        unless (self[SERVICE_TYPE] - ['*', 'email']).empty?()
          raise NotImplementedError.new("Unsupported service #{self[SERVICE_TYPE]}")
        end
      end
      
      def public_key()
        begin
          @public_key ||= OpenSSL::PKey::RSA.new(self[PUBLIC_KEY])
        rescue OpenSSL::PKey::RSAError
          FailureError.new("Public key error: #{$!.message}")
        end
      end
      
      def allowed_hash_algorithm?(algorithm)
        self[HASH_ALGORITHM].include?(algorithm.split('-', 2).last())
      end
      
      def allowed_key_algorithm?(algorithm)
        self[KEY_TYPE] == algorithm.split('-', 2).first()
      end
      
      
      def testing?()
        #RFC 6376 Section 3.6: y  This domain is testing DKIM.  Verifiers MUST NOT treat messages
        #from Signers in testing mode differently from unsigned email,
        #even should the signature fail to verify.  Verifiers MAY wish
        #to track testing mode results to assist the Signer.
        self[FLAGS].include?('t')
      end
      
      def require_exact_user_identifier_domain?()
        #RFC 6376 Section 3.6: s  Any DKIM-Signature header fields using the "i=" tag MUST have
        #the same domain value on the right-hand side of the "@" in the
        #"i=" tag and the value of the "d=" tag.  That is, the "i="
        #domain MUST NOT be a subdomain of "d=".  Use of this flag is
        #RECOMMENDED unless subdomaining is required.
        self[FLAGS].include?('s')
      end
      
      
    private
      def encoder_for(key)
        case key
        when FLAGS, SERVICE_TYPE, HASH_ALGORITHM
          Encodings::PlainText.new().extend(Encodings::ColonSeparated)
        when KEY_TYPE, NOTES, VERSION
          Encodings::PlainText.new()
        when PUBLIC_KEY
          Encodings::Base64.new()
        else
          raise NotImplementedError.new("unknown key: #{key}")
        end
      end
    end
  end
end