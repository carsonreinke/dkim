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
          begin
            record = Resolv::DNS.open do |dns|
              dns.getresources("#{selector}.#{NAMESPACE}.#{domain}", Resolv::DNS::Resource::IN::TXT)
            end
          rescue Resolv::ResolvTimeout
            raise KeyUnavailableError.new($!.message)
          rescue Resolv::NXDomain
            raise NoKeyForSignatureError.new($!.message)
          rescue Resolv::ResolvError
            raise TemporaryFailureError.new($!.message)
          end
          
          #RFC 6376 3.6.2.2 "if there are multiple records in an RRset, the results are undefined."
          raise FailureError.new('Too many records') if record.size() > 1
          
          record = record.first()
          return nil if record.nil?()
          return Policy.new(record.data())
        end
      end
    end
  end
end