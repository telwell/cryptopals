require 'rspec'
require 'HTTParty'
require_relative '../crypto'
require_relative '../converter'

RSpec.describe Crypto, "set 1" do
	
	
	context "question 1" do
		it "should be able to convert hex to base64" do
			encoded = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
			expected = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
			expect(Converter.hex_to_base64(encoded)).to eq(expected)
		end
	end
	
	
	context "question 2" do
		it "should be able to produce two strings XOR combination" do
			hex_a = '1c0111001f010100061a024b53535009181c'
			hex_b = '686974207468652062756c6c277320657965'
			expected = '746865206b696420646f6e277420706c6179'
			expect(Crypto.hex_xor(hex_a, hex_b)).to eq(expected)
		end
	end
	
	
	context "question 3" do
		it "should be able to break a XOR cipher" do
			cipher = Converter.hex_to_bytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
			# ans = "Cooking MC's like a pound of bacon"
			result = Crypto.break_xor(cipher)
			# puts Crypto.xor_key(cipher, result[0])
			expect(result[0]).to eq("X")
		end
	end
	
	
	context "question 4" do
		it "should be able to detect XOR manipulation" do
			cipher_http = HTTParty.get('https://cryptopals.com/static/challenge-data/4.txt')
			key = ''
			key, cleartext = Crypto.detect_xor(cipher_http.body)
			expect(key).to eq('5')
			expect(cleartext.strip).to eq('Now that the party is jumping')
		end
	end
	
	
end
