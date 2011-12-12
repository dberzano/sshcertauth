#!/usr/bin/ruby

#
# Ruby script.
#

#curl -L \
#  --cert $HOME/.globus/usercert.pem \
#  --key $HOME/.globus/userkey.pem \
#  --capath /opt/alisw/alien/globus/share/certificates \
#  https://pmaster.to.infn.it/auth?o=xml | pygmentize -lxml

require 'rexml/document'
require 'net/https'
require 'openssl/x509'
require 'pp'

# Global variables
userCertPath = "#{ENV['HOME']}/.globus/usercert.pem"
userKeyPath = "#{ENV['HOME']}/.globus/userkey.pem"

http = Net::HTTP.new('pmaster.to.infn.it', Net::HTTP.https_default_port)
http.use_ssl = true

File.open(userCertPath) do |certFile|
  http.cert = OpenSSL::X509::Certificate.new(certFile.read)
end

File.open(userKeyPath) do |keyFile|
  http.key = OpenSSL::PKey::RSA.new(keyFile.read)
end

# Make the request
rawXml = nil
http.request_get('/auth/?o=xml') { |httpResp|
  if httpResp.code.to_i == 200 && httpResp['content-type'] == 'text/xml'
    rawXml = httpResp.read_body
  end
}



puts '=== BEGIN HTTP RESPONSE ==='
puts rawXml
puts '=== END HTTP RESPONSE ==='

xml = REXML::Document.new( rawXml );

puts '=== BEGIN XML ==='
xmlFmt = REXML::Formatters::Pretty.new
rawXmlPretty = String.new
xmlFmt.write(xml, rawXmlPretty)
puts rawXmlPretty
puts '=== END XML ==='


# Variables useful for connection
serverFqdn = nil
serverPort = 22
userName = nil
isValid = false

# Get the server
xml.elements.each('sshauth/server') { |serverElm|

  serverElm.elements.each('name') { |nameElm|
    serverFqdn = nameElm.text
    break
  }

  serverElm.elements.each('port') { |portElm|
    serverPort = portElm.text.to_i
    break
  }

  break # only one server supported at the moment

}

# Get the username
xml.elements.each('sshauth/auth') { |authElm|

  authElm.elements.each('user') { |userElm|
    userName = userElm.text
    break
  }

  authElm.elements.each('valid') { |validElm|
    if validElm.text.downcase == 'true'
      isValid = true
    end
    break
  }

}

# Check if everything is alright
if serverPort >= 0 and serverFqdn and isValid
  sshCmd = "ssh -p #{serverPort} -i ~/.globus/userkey.pem #{userName}@#{serverFqdn}"
  puts sshCmd
  #exec sshCmd
else
  puts "Cannot authenticate, sorry"
end
