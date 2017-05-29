require 'rspec'
require 'HTTParty'
require_relative '../shared/crypto'
require_relative '../shared/converter'

RSpec.describe Crypto, "set 2" do
  
  
  context "question 1" do
    it "should be able to impliment PKCS#7 padding" do
      unpadded = "YELLOW SUBMARINE"
      padded = Crypto.right_pad(unpadded, 20)
      expect(padded.length).to eq(20)
      expect(padded[-1]).to eq("\x04")
    end
  end
  
  
end
