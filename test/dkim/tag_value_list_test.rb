
require 'test_helper'

module Dkim
  class TagValueListTest < MiniTest::Unit::TestCase
    def test_replacement
      @list = TagValueList.new

      @list['a'] = '1'
      @list['b'] = '2'
      @list['c'] = '3'
      assert_equal 'a=1; b=2; c=3', @list.to_s

      @list['b'] = '4'
      assert_equal 'a=1; b=4; c=3', @list.to_s
    end
    def test_correct_format
      @list = TagValueList.new

      @list['b'] = '2'
      @list['a'] = '1'
      @list['c'] = '!@#$%^'

      assert_equal 'b=2; a=1; c=!@#$%^', @list.to_s
    end
    def test_parse
      @list = TagValueList.parse 'a=1; b=2; c=3'
      
      assert_equal '1', @list['a']
      assert_equal '2', @list['b']
      assert_equal '3', @list['c']
    end
    def test_parse_whitespace
      @list = TagValueList.parse 'a=1;b= 2 ; c =3 '
      
      assert_equal '1', @list['a']
      assert_equal '2', @list['b']
      assert_equal '3', @list['c']
    end
  end
end

