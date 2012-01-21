require "simplecov"

include SwtFederation

SimpleCov.start do
  root(File.join(File.dirname(__FILE__), '../'))
  add_filter '/spec/'
end

require_relative ("../lib/swt_federation.rb")

describe "TokenHandler" do

  it "Should return a valid token when wresult is valid" do
    token_key = Base64.encode64("my_token_key")
    SwtFederation::TokenHandler.token_type = 'http://schemas.xmlsoap.org/ws/2009/11/swt-token-profile-1.0'
    SwtFederation::TokenHandler.issuer = 'https://myissuer.net/'
    SwtFederation::TokenHandler.token_key = token_key
    SwtFederation::TokenHandler.realm = 'http://0.0.0.0:8080/login/'  
    expires = Time.now + 60
    expires_on= (expires).utc.strftime("%Y-%m-%dT%H:%M:%S.00Z")
    expires_on_int = expires.to_i
    puts "espiration: #{expires_on}"
    swt = "http%3a%2f%2fschemas.xmlsoap.org%2fws%2f2005%2f05%2fidentity%2fclaims%2femailaddress=nicopaez%40southworks.net&http%3a%2f%2fschemas.xmlsoap.org%2fws%2f2005%2f05%2fidentity%2fclaims%2fname=nicopaez&http%3a%2f%2fschemas.microsoft.com%2faccesscontrolservice%2f2010%2f07%2fclaims%2fidentityprovider=https%3a%2f%2flogin.southworks.net%2f&Audience=http%3a%2f%2f0.0.0.0%3a8080%2flogin%2f&ExpiresOn=#{expires_on_int}&Issuer=https%3a%2f%2fmyissuer.net%2f"
    hmac_value = Base64.encode64(OpenSSL::HMAC.digest(OpenSSL::Digest::Digest.new('sha256'),Base64.decode64(token_key),swt)).chomp
    hmac_value = CGI.escape(hmac_value)
    puts "input hmac is #{hmac_value}" 
    swt = swt + "&HMACSHA256=#{hmac_value}"
    binary_encoded_token = Base64.encode64(swt)
    token = '<t:RequestSecurityTokenResponse Context="/" xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust"><t:Lifetime><wsu:Created xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">{expirationTime}</wsu:Created><wsu:Expires xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">{expirationTime}</wsu:Expires></t:Lifetime><wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy"><EndpointReference xmlns="http://www.w3.org/2005/08/addressing"><Address>http://0.0.0.0:8080/login/</Address></EndpointReference></wsp:AppliesTo><t:RequestedSecurityToken><wsse:BinarySecurityToken wsu:Id="uuid:bcdaf64f-1854-452a-9cae-1c1ff5077fee" ValueType="http://schemas.xmlsoap.org/ws/2009/11/swt-token-profile-1.0" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">{binaryToken}</wsse:BinarySecurityToken></t:RequestedSecurityToken><t:TokenType>http://schemas.xmlsoap.org/ws/2009/11/swt-token-profile-1.0</t:TokenType><t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType><t:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</t:KeyType></t:RequestSecurityTokenResponse>'
    token = token.sub('{expirationTime}', expires_on)
    token = token.sub('{expirationTime}', expires_on)
    token = token.sub('{binaryToken}', binary_encoded_token)
    @wresult = token

    token_handler = SwtFederation::TokenHandler.new(@wresult)

    token_handler.is_token_valid?.should == true
  end

  it "Should return an invalid token when wresult is expired" do
    token_key = Base64.encode64("my_token_key")
    SwtFederation::TokenHandler.token_type = 'http://schemas.xmlsoap.org/ws/2009/11/swt-token-profile-1.0'
    SwtFederation::TokenHandler.issuer = 'https://myissuer.net/'
    SwtFederation::TokenHandler.token_key = token_key
    SwtFederation::TokenHandler.realm = 'http://0.0.0.0:8080/login/'  
    expires = Time.now - 60
    expires_on= (expires).utc.strftime("%Y-%m-%dT%H:%M:%S.00Z")
    expires_on_int = expires.to_i
    puts "espiration: #{expires_on}"
    swt = "http%3a%2f%2fschemas.xmlsoap.org%2fws%2f2005%2f05%2fidentity%2fclaims%2femailaddress=nicopaez%40southworks.net&http%3a%2f%2fschemas.xmlsoap.org%2fws%2f2005%2f05%2fidentity%2fclaims%2fname=nicopaez&http%3a%2f%2fschemas.microsoft.com%2faccesscontrolservice%2f2010%2f07%2fclaims%2fidentityprovider=https%3a%2f%2flogin.southworks.net%2f&Audience=http%3a%2f%2f0.0.0.0%3a8080%2flogin%2f&ExpiresOn=#{expires_on_int}&Issuer=https%3a%2f%2fmyissuer.net%2f"
    hmac_value = Base64.encode64(OpenSSL::HMAC.digest(OpenSSL::Digest::Digest.new('sha256'),Base64.decode64(token_key),swt)).chomp
    hmac_value = CGI.escape(hmac_value)
    puts "input hmac is #{hmac_value}" 
    swt = swt + "&HMACSHA256=#{hmac_value}"
    binary_encoded_token = Base64.encode64(swt)
    token = '<t:RequestSecurityTokenResponse Context="/" xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust"><t:Lifetime><wsu:Created xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">{expirationTime}</wsu:Created><wsu:Expires xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">{expirationTime}</wsu:Expires></t:Lifetime><wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy"><EndpointReference xmlns="http://www.w3.org/2005/08/addressing"><Address>http://0.0.0.0:8080/login/</Address></EndpointReference></wsp:AppliesTo><t:RequestedSecurityToken><wsse:BinarySecurityToken wsu:Id="uuid:bcdaf64f-1854-452a-9cae-1c1ff5077fee" ValueType="http://schemas.xmlsoap.org/ws/2009/11/swt-token-profile-1.0" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">{binaryToken}</wsse:BinarySecurityToken></t:RequestedSecurityToken><t:TokenType>http://schemas.xmlsoap.org/ws/2009/11/swt-token-profile-1.0</t:TokenType><t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType><t:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</t:KeyType></t:RequestSecurityTokenResponse>'
    token = token.sub('{expirationTime}', expires_on)
    token = token.sub('{expirationTime}', expires_on)
    token = token.sub('{binaryToken}', binary_encoded_token)

    token_handler = SwtFederation::TokenHandler.new(@wresult)

    token_handler.is_token_valid?.should == false
  end

  it "Should return an invalid token when hmac is wresult does not match" do
    token_key = Base64.encode64("my_token_key")
    SwtFederation::TokenHandler.token_type = 'http://schemas.xmlsoap.org/ws/2009/11/swt-token-profile-1.0'
    SwtFederation::TokenHandler.issuer = 'https://myissuer.net/'
    SwtFederation::TokenHandler.token_key = token_key
    SwtFederation::TokenHandler.realm = 'http://0.0.0.0:8080/login/'  
    expires = Time.now - 60
    expires_on= (expires).utc.strftime("%Y-%m-%dT%H:%M:%S.00Z")
    expires_on_int = expires.to_i
    puts "espiration: #{expires_on}"
    swt = "http%3a%2f%2fschemas.xmlsoap.org%2fws%2f2005%2f05%2fidentity%2fclaims%2femailaddress=nicopaez%40southworks.net&http%3a%2f%2fschemas.xmlsoap.org%2fws%2f2005%2f05%2fidentity%2fclaims%2fname=nicopaez&http%3a%2f%2fschemas.microsoft.com%2faccesscontrolservice%2f2010%2f07%2fclaims%2fidentityprovider=https%3a%2f%2flogin.southworks.net%2f&Audience=http%3a%2f%2f0.0.0.0%3a8080%2flogin%2f&ExpiresOn=#{expires_on_int}&Issuer=https%3a%2f%2fmyissuer.net%2f"
    hmac_value = "anything"
    hmac_value = CGI.escape(hmac_value)
    puts "input hmac is #{hmac_value}" 
    swt = swt + "&HMACSHA256=#{hmac_value}"
    binary_encoded_token = Base64.encode64(swt)
    token = '<t:RequestSecurityTokenResponse Context="/" xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust"><t:Lifetime><wsu:Created xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">{expirationTime}</wsu:Created><wsu:Expires xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">{expirationTime}</wsu:Expires></t:Lifetime><wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy"><EndpointReference xmlns="http://www.w3.org/2005/08/addressing"><Address>http://0.0.0.0:8080/login/</Address></EndpointReference></wsp:AppliesTo><t:RequestedSecurityToken><wsse:BinarySecurityToken wsu:Id="uuid:bcdaf64f-1854-452a-9cae-1c1ff5077fee" ValueType="http://schemas.xmlsoap.org/ws/2009/11/swt-token-profile-1.0" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">{binaryToken}</wsse:BinarySecurityToken></t:RequestedSecurityToken><t:TokenType>http://schemas.xmlsoap.org/ws/2009/11/swt-token-profile-1.0</t:TokenType><t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType><t:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</t:KeyType></t:RequestSecurityTokenResponse>'
    token = token.sub('{expirationTime}', expires_on)
    token = token.sub('{expirationTime}', expires_on)
    token = token.sub('{binaryToken}', binary_encoded_token)

    token_handler = SwtFederation::TokenHandler.new(@wresult)

    token_handler.is_token_valid?.should == false
  end

end
