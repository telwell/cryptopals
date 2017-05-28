require 'pry'
require_relative 'converter'
require_relative 'constants'

class Crypto
  
  
  # @param str_a: String
  # @param str_b: String
  # @return String of XOR'd bytes packed into a string
  def self.xor_str(str_a, str_b)
    raise "Length of input strings doesn't match!" if str_a.length != str_b.length
    str_a.bytes.zip(str_b.bytes).map { |x,y| x^y }.pack('C*')
  end
  
  
  def self.hex_xor(hex_a, hex_b)
    Converter.str_to_hex(xor_str(Converter.hex_to_bytes(hex_a),Converter.hex_to_bytes(hex_b)))
  end
  
  
  # @param str: String
  # @param key: String (of any length <= str)
  # @return String from xor_str
  def self.xor_key(str, key)
    key_str = key * str.length
    xor_str(str, key_str.slice(0,str.length))
  end
  
  
  def self.freq_hist(str)
    hist = Hash.new(0)
    only_letters = str.scan(/[A-Za-z ]/).join.downcase
    total = only_letters.length
    only_letters.each_char { |c| hist[c] += 1 }
    hist.each_key { |k| hist[k] /= Float(total) }
    return hist, total
  end
  
  
  def self.pearson_chi2(observed, expected)
    chi2 = 0
    expected.keys.each do |c|
      val = (observed[c] - expected[c])**2 / expected[c]
      chi2 += val
    end
    if chi2 >= 2
      chi2 = 1
    end
    return chi2 - 1
  end
  
  
  # @param str: String to be analyzed
  def self.score_string(str)
    hist, total = freq_hist(str)
    return pearson_chi2(hist, ENGLISH_LETTER_FREQUENCY)
  end
  
  
  def self.break_xor(cipher_text)
    key = ''
    current_max_score = 0
    for c in 0..255 # Number of possible values for one Byte
      result = xor_key(cipher_text, c.chr.to_s)
      score = score_string(result)
      if score > current_max_score
        current_max_score = score
        key = c.chr.to_s
      end
    end
    return key, current_max_score
  end
  
  
  def self.detect_xor(s)
    current_max_score, validkey, validline = 0, '', ''
    s.each_line do |l|
      cipher_text = Converter.hex_to_bytes(l.strip)
      key, score = break_xor(cipher_text)
      if key != '' && xor_key(cipher_text, key).scan(/[^a-zA-Z\s]/).count == 0
        # puts "Score: #{score} | #{xor_key(cipher_text, key)}\n"
        if score > current_max_score
          current_max_score = score
          validkey = key
          validline = xor_key(cipher_text, key)
        end
      end
    end
    return validkey, validline
  end
  
  
end