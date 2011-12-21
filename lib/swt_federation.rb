# http://blog.thepete.net/2010/11/creating-and-publishing-your-first-ruby.html
require "swt_federation/version"

require 'nokogiri'
require 'time'
require 'base64'
require 'cgi'
require 'openssl'


module SwtFederation

  class TokenHandler
    class << self; attr_accessor :realm, :issuer, :token_key, :token_type end
    
    attr_reader :validation_errors, :claims

    def initialize(wresult)
      @validation_errors = []
      @claims={}
      @wresult=Nokogiri::XML(wresult)

      parse_response()
    end
  
    def is_valid?
      @validation_errors.empty?
    end
  
    #parse through the document, performing validation & pulling out claims
    def parse_response
      parse_address()
      parse_expires()
      parse_token_type()
      parse_token()
    end
 
    #does the address field have the expected address?
    def parse_address
      address = get_element('//t:RequestSecurityTokenResponse/wsp:AppliesTo/addr:EndpointReference/addr:Address')
      @validation_errors << "Address field is empty." and return if address.nil?
      @validation_errors << "Address field is incorrect." unless address == self.class.realm
    end
  
    #is the expire value valid?
    def parse_expires
      expires = get_element('//t:RequestSecurityTokenResponse/t:Lifetime/wsu:Expires')
      @validation_errors << "Expiration field is empty." and return if expires.nil?
      @validation_errors << "Invalid format for expiration field." and return unless /^(-?(?:[1-9][0-9]*)?[0-9]{4})-(1[0-2]|0[1-9])-(3[0-1]|0[1-9]|[1-2][0-9])T(2[0-3]|[0-1][0-9]):([0-5][0-9]):([0-5][0-9])(\.[0-9]+)?(Z|[+-](?:2[0-3]|[0-1][0-9]):[0-5][0-9])?$/.match(expires)
      @validation_errors << "Expiration date occurs in the past." unless Time.now.utc.iso8601 < Time.iso8601(expires).iso8601
    end
  
    #is the token type what we expected?
    def parse_token_type
      token_type = get_element('//t:RequestSecurityTokenResponse/t:TokenType')
      @validation_errors << "TokenType field is empty." and return if token_type.nil?
      @validation_errors << "Invalid token type." unless token_type == self.class.token_type
    end
  
    #parse the binary token
    def parse_token
      binary_token = get_element('//t:RequestSecurityTokenResponse/t:RequestedSecurityToken/wsse:BinarySecurityToken')
      @validation_errors << "No binary token exists." and return if binary_token.nil?
    
      decoded_token = Base64.decode64(binary_token)
      name_values={}
      decoded_token.split('&').each do |entry|
        pair=entry.split('=') 
        name_values[CGI.unescape(pair[0]).chomp] = CGI.unescape(pair[1]).chomp
      end

      @validation_errors << "Response token is expired." if Time.now.to_i > name_values["ExpiresOn"].to_i
      @validation_errors << "Invalid token issuer." unless name_values["Issuer"]=="#{self.class.issuer}"
      @validation_errors << "Invalid audience." unless name_values["Audience"] =="#{self.class.realm}"
 
      # is HMAC valid?
      token_hmac = decoded_token.split("&HMACSHA256=")
      swt=token_hmac[0]
      @validation_errors << "HMAC does not match computed value." unless name_values['HMACSHA256'] == Base64.encode64(OpenSSL::HMAC.digest(OpenSSL::Digest::Digest.new('sha256'),Base64.decode64(self.class.token_key),swt)).chomp
    
      # remove non-claims from collection and make claims available

      @claims = name_values.reject {|key, value| !key.include? '/claims/'}
    end
  
    #given an path, return the content of the first matching element
    def get_element(xpath_statement)
      begin
        @wresult.xpath(xpath_statement,
                't'=>'http://schemas.xmlsoap.org/ws/2005/02/trust',
                'wsu'=>'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd',
                'wsp'=>'http://schemas.xmlsoap.org/ws/2004/09/policy',
                'wsse'=>'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
                'addr'=>'http://www.w3.org/2005/08/addressing')[0].content
      rescue
        nil
      end
    end
  end

end
