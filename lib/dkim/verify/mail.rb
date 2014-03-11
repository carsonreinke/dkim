require 'openssl'
require 'dkim/body'
require 'dkim/header'
require 'dkim/verify/signature'
require 'dkim/canonicalized_headers'
require 'dkim/verify/errors/permanent_failure_errors'

module Dkim
  module Verify
    #
    # RFC 5322 
    # RFC 6854
    # RFC 4686 Analysis of Threats Motivating DomainKeys Identified Mail (DKIM)
    # RFC 4871 DomainKeys Identified Mail (DKIM) Signatures Proposed Standard
    # RFC 5617 DomainKeys Identified Mail (DKIM) Author Domain Signing Practices (ADSP)
    # RFC 5585 DomainKeys Identified Mail (DKIM) Service Overview
    # RFC 5672 RFC 4871 DomainKeys Identified Mail (DKIM) SignaturesUpdate
    # RFC 5863 DKIM Development, Deployment, and Operations
    # RFC 6376 DomainKeys Identified Mail (DKIM) Signatures Draft Standard
    # RFC 6377 DomainKeys Identified Mail (DKIM) and Mailing Lists
    #
    class Mail
      #
      #SUCCESS:  a successful verification
      #PERMFAIL:  a permanent, non-recoverable error such as a signature
      #   verification failure
      #TEMPFAIL:  a temporary, recoverable error such as a DNS query timeout
      #
      class Result < Struct.new(:signature, :status, :error)
        STATUSES = [:success, :permfail, :tempfail]
        
        #Define status methods
        STATUSES.each do |status|
          define_method(:"#{status}?"){ self.status == status }
        end
      end
      
      #
      #
      #
      def initialize(message, options = {})
        message = message.to_s.gsub(/\r?\n/, "\r\n")
        headers, body = message.split(/\r?\n\r?\n/, 2)
        @original_message = message
        @headers = Header.parse(headers)
        @body = Body.new(body)
        @signatures = Signature.find_all(@headers)
      end
      
      attr_reader :signatures
      
      #
      # 
      #
      def verify_all(&block)
        self.signatures.map do |signature|
          result = Result.new(signature)
          
          begin
            self.verify(signature)
            result.status = :success
          rescue PermanentFailureError
            result.status, result.error = :permfail, $!
          rescue TemporaryFailureError
            result.status, result.error = :tempfail, $!
          rescue StandardError
            result.status, result.error = :permfail, $!
          end
          
          result
        end
      end
      
      #
      # SUCCESS = no error
      # PERMFAIL = PermanentFailureError
      # TEMPFAIl = TemporaryFailureError
      #
      def verify!(signature)
        #Validate signature and policy
        signature.validate!
        signature.policy.validate!
        
        #RFC 6376 Section 6.1.1: Verifiers MUST confirm that the domain specified in the "d=" tag is
        #the same as or a parent domain of the domain part of the "i=" tag.
        #If not, the DKIM-Signature header field MUST be ignored, and the
        #Verifier should return PERMFAIL (domain mismatch).
        raise DomainMismatchError.new() unless signature.is_user_identifier_domain_valid?
        
        #RFC 6376 Section 6.1.1: Verifiers MAY ignore the DKIM-Signature header field and return
        #PERMFAIL (signature expired) if it contains an "x=" tag and the
        #signature has expired.
        raise SignatureExpiredError.new() if signature.expired?()
        
        #RFC 6376 Section 6.1.1: Verifiers MAY ignore the DKIM-Signature header field if the domain
        #used by the Signer in the "d=" tag is not associated with a valid
        #signing entity.
        raise UnacceptableSignatureHeaderError.new('Domain is unacceptable') if signature.is_domain_unacceptable?()
        
        #RFC 6376 Section 6.1.2.6: If the "h=" tag exists in the public-key record and the hash
        #algorithm implied by the "a=" tag in the DKIM-Signature header
        #field is not included in the contents of the "h=" tag, the
        #Verifier MUST ignore the key record and return PERMFAIL
        #(inappropriate hash algorithm).
        raise InappropriateHashAlgorithmError.new() unless signature.policy.allowed_hash_algorithm?(signature[DkimHeader::ALGORITHM])
        
        #RFC 6376 Section 6.1.2.8: If the public-key data is not suitable for use with the algorithm
        #and key types defined by the "a=" and "k=" tags in the DKIM-
        #Signature header field, the Verifier MUST immediately return
        #PERMFAIL (inappropriate key algorithm).
        raise InappropriateKeyAlgorithm.new() unless signature.policy.allowed_key_algorithm?(signature[DkimHeader::ALGORITHM])
        
        #
        #Hash verification
        #
        #RFC 6376 Section 6.1.3.1-2
        body = self.canonical_body(signature.body_canonicalization(), signature[DkimHeader::BODY_LENGTH])
        hash = signature.algorithm().digest(body)
        #RFC 6376 Section 6.1.3.3
        raise BodyHashDidNotVerifyError.new() unless hash == signature[DkimHeader::HASH]
        
        #
        #Signature verification
        #
        #RFC 6376 Section 6.1.3.4
        headers = canonical_header(signature[DkimHeader::HEADERS], signature.header_canonicalization()).concat(
          signature.original_without_signature().to_s(signature.header_canonicalization())
        )
        unless signature.policy.public_key().verify(signature.algorithm(), signature[DkimHeader::SIGNATURE], headers)
           raise SignatureDidNotVerifyError.new()
        end
        
        nil
      end
      
      #
      #
      #
      def verify(signature)
        begin
          self.verify!(signature)
        rescue Error
          return false
        end
      end
      
      
    protected
      #TODO Copied methods from SignedMail, yuck!
      def canonicalized_headers(signable_headers)
        CanonicalizedHeaders.new(@headers, signed_headers(signable_headers))
      end

      # @return [Array<String>] lowercased names of headers in the order they are signed
      def signed_headers(signable_headers)
        @headers.map(&:relaxed_key).select do |key|
          signable_headers.map(&:downcase).include?(key)
        end
      end

      # @return [String] Signed headers of message in their canonical forms
      def canonical_header(signable_headers, header_canonicalization)
        canonicalized_headers(signable_headers).to_s(header_canonicalization)
      end

      # @return [String] Body of message in its canonical form
      def canonical_body(body_canonicalization, limit = nil)
        body = @body.to_s(body_canonicalization)
        size = body.bytesize
        raise UnsignedContentError.new("Limit is too large #{limit} > #{size}") if (limit || 0) > size
        return body.byteslice(0..(limit || -1))
      end
    end
  end
end
