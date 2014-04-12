require 'resolv'
require 'dkim/verify/policy'
require 'dkim/verify/errors/permanent_failure_errors'
require 'dkim/verify/errors/temporary_failure_errors'

module Dkim
  module Verify
    class Resolver
      class << self
        #TODO Timeout?
        NAMESPACE = '_domainkey'.freeze()
        
        def query(domain, selector)
          Resolv::DNS.open do |dns|
            dns.getresources("#{selector}.#{NAMESPACE}.#{domain}", Resolv::DNS::Resource::IN::TXT)
          end
        end
        
        def get_policy(domain, selector)
          begin
            records = self.query(domain, selector)
          rescue Resolv::ResolvTimeout
            raise KeyUnavailableError.new($!.message)
          rescue Resolv::NXDomain
            raise NoKeyForSignatureError.new($!.message)
          rescue Resolv::ResolvError
            raise TemporaryFailureError.new($!.message)
          end

          #RFC 6376 3.6.2.2 "if there are multiple records in an RRset, the results are undefined."
          raise FailureError.new('Too many records') if records.size() > 1
          record = records.first()
          #RFC 6376 6.1.2.3
          raise NoKeyForSignatureError.new() if record.nil?()
          return Policy.new(record.strings.join('')) #Not sure why this #data only returns first?
        end
      end
    end
  end
end