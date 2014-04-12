require 'test_helper'
require 'dkim/verify/mail'

module Dkim
  module Verify
    class MailTest < MiniTest::Unit::TestCase
      def test_verify
        verifier = Dkim::Verify::Mail.new(
          EXAMPLEEMAIL.dup().prepend(
          <<-MAIL
DKIM-Signature: v=1; a=rsa-sha256; s=brisbane; d=example.com;
  c=simple/simple; q=dns/txt; i=joe@football.example.com;
  h=Received : From : To : Subject : Date : Message-ID;
  bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
  b=AuUoFEfDxTDkHlLXSZEpZj79LICEps6eda7W3deTVFOk4yAUoqOB
  4nujc7YopdG5dWLSdNg6xNAZpOPr+kHxt1IrE+NahM6L/LbvaHut
  KVdkLLkpVaVVQPzeRDI009SO2Il5Lu7rDNH6mZckBdrIx0orEtZV
  4bmp/YzhwvcubU4=;
          MAIL
          )
        )
        
        assert_equal 1, verifier.signatures.size
        #TODO
        verifier.verify!(verifier.signatures.first)
      end
    end
  end
end