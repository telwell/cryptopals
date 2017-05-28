require 'pry'
require 'base64'

class Converter
  
  
  def self.hex_to_bytes(input)
    [input].pack("H*")
  end
  
  
  def self.str_to_hex(input)
    input.unpack("H*").first
  end
  
  
  def self.hex_to_base64(input)
    Base64.strict_encode64(hex_to_bytes(input))
  end
  
  
  def self.base64_to_hex(input)
    str_to_hex(Base64.decode64(input))
  end
  
  
  def self.base64_decode(input)
    Base64.decode64(input)
  end
  
  
end
