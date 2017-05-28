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
    chi2 = false if chi2 == 1.0
    return chi2
  end
  
  
  def self.custom_score(observed, expected)
    score = 0
    observed.keys.each do |c|
      val = (expected[c] * 100) * observed[c]
      score += val
    end
    score
  end
  
  
  # @param str: String to be analyzed
  def self.score_string(str)
    hist, total = freq_hist(str)
    return pearson_chi2(hist, ENGLISH_LETTER_FREQUENCY)
    # return custom_score(hist, ENGLISH_LETTER_FREQUENCY)
  end
  
  
  def self.break_xor(cipher_text, debug = false)
    key = ''
    current_min_score = nil
    for c in 0..255 # Number of possible values for one Byte
      result = xor_key(cipher_text, c.chr.to_s)
      score = score_string(result)
      # p "Score: #{score} | #{result}\n" if score && score < 2.0
      if score and (current_min_score.nil? or score < current_min_score)
        current_min_score = score
        key = c.chr.to_s
        p "Key: #{key} | Score: #{score} | #{result}\n" if debug
      end
    end
    return key, current_min_score
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
  
  
  # Implimentation of this hamming distance: https://stackoverflow.com/a/6397116/2187161
  def self.hamming_distance(s1, s2)
    raise "ERROR: Hamming: Non equal lengths" if s1.length != s2.length
    dist = 0
    s1.bytes.zip(s2.bytes).each do |x,y|
      dist += (x^y).to_s(2).count('1')
    end
    dist
  end
  
  
  def self.find_key_len(cipher_str)
    key_length = 0
    min_average = nil
    2.upto(40) do |test_key_length|
      normalized_edit_dist = []
      # HACK: I should probably be doing this with bytes
      cipher_chunks = cipher_str.scan(/.{#{test_key_length}}/)
      # When test_key_length is 40 we have 42 cipher chunks, meaning we can 
      # test a maximum of 21 times for every test_key_length
      21.times do |i|
        start_index = 2*i
        normalized_edit_dist << (hamming_distance(cipher_chunks[start_index], cipher_chunks[start_index+1]) / Float(test_key_length))
      end
      average = normalized_edit_dist.inject{ |sum, el| sum + el }.to_f / normalized_edit_dist.count
      if min_average.nil? or average < min_average
        min_average = average
        key_length = test_key_length
      end
    end
    key_length
  end
  
  
  def self.break_xor_key(cipher_text, key_length)
    cipher_chunks = []
    cipher_text = cipher_text.bytes
    # Leave of any remaning bits that can't fit into the key_length
    (Float(cipher_text.length)/key_length).floor().times do |i|
      start_index = i * key_length
      cipher_chunks << cipher_text.slice(start_index, key_length)
    end
    final_key = []
    cipher_chunks.transpose.each do |chunk|
      key, score = break_xor(chunk.pack('C*'))
      # p "Score: #{score} | #{key}"
      final_key << key
    end
    final_key.join('')
  end
  
  
end