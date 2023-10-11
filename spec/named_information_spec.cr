require "./spec_helper"

module NamedInformation
  describe NamedInformation do
    test_data = "30820122300d06092a864886f70d01010105000382010f003082010a0282010100a25f83da9bd9f17a3a3667bafd5a940ecf16d55a553a5ed403b1658e6dcfa3b7dba4e7cc0f52c67d351dc468c2bd7b9ddbe40ad710cdf95320ee0dd7566e5b7aae2c5f830a193c725896d686e80ee694eb5cf2903ef3a88a8856b6cd3638762297b16b3c9c07f34f9708a1bc29389b81062b7460387a932f39be1234096e0b5710b7a37bf2c6eed6c1e5ecaec59c8314f46b58e2def2ffc97707e3f34c97cf1a289e38a1b3934175a1a4763f4d78d744d61ae3cee25dc5784cb531222ec74b8c6f56785ca1c4c01dcae5b944d7e9909cbceeb0a2b1dcda6da00ff6ad1e2c12a2a766603e36d49141c2f2e769392c9dd2dfb5a34495487c876489ddbf0501eedd0203010001".hexbytes
    test_sha = "53269057e12fe2b74ba07c892560a2d753877eb62ff44d5a19002530ed97ffe4".hexbytes

    it "validates test data" do
      OpenSSL::Digest.new("SHA256").update(test_data).final.should eq test_sha
    end

    it "should generate a ni URI formatted strings" do
      NamedInformation.generate_uri("Hello World!").should eq("ni:///sha-256;f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk")
      NamedInformation.generate_uri("Hello World!", authority: "example.com").should eq("ni://example.com/sha-256;f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk")

      NamedInformation.generate_uri(test_data).should eq("ni:///sha-256;UyaQV-Ev4rdLoHyJJWCi11OHfrYv9E1aGQAlMO2X_-Q")
    end

    it "should generate a well known URL" do
      NamedInformation.generate_well_known("Hello World!", authority: "example.com").should eq("http://example.com/.well-known/ni/sha-256/f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk")
      NamedInformation.generate_well_known(test_data, authority: "example.com").should eq("http://example.com/.well-known/ni/sha-256/UyaQV-Ev4rdLoHyJJWCi11OHfrYv9E1aGQAlMO2X_-Q")
    end

    it "should generate a URL segment" do
      NamedInformation.generate_segment("Hello World!").should eq("sha-256;f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk")
      NamedInformation.generate_segment(test_data).should eq("sha-256;UyaQV-Ev4rdLoHyJJWCi11OHfrYv9E1aGQAlMO2X_-Q")
    end

    it "should generate a human speakable segment" do
      NamedInformation.generate_human_speakable(test_data, truncate: 32).should eq("nih:sha-256-32;5326-9057;b")
      NamedInformation.generate_human_speakable(test_data, truncate: 120).should eq("nih:sha-256-120;5326-9057-e12f-e2b7-4ba0-7c89-2560-a2;f")
      NamedInformation.generate_human_speakable(test_data, algorithm: 3).should eq("nih:3;5326-9057-e12f-e2b7-4ba0-7c89-2560-a2;f")
    end

    it "should make it simple to compare hashes" do
      uri = Hash.new NamedInformation.generate_uri("Hello World!", authority: "example.com")
      uri.hash.should eq("f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk")
      uri.algorithm.should eq("sha-256")
      uri.authority.should eq("example.com")

      well = Hash.new NamedInformation.generate_well_known("Hello World!", authority: "example.com")
      seg = Hash.new NamedInformation.generate_segment("Hello World!")

      uri.should eq well
      uri.should eq seg
      seg.should eq well

      uri.matches?("Hello World!", "example.com").should eq true
    end

    it "should raise if a human speakable hash is incorrect" do
      Hash.new("nih:sha-256-32;5326-9057;b")
      expect_raises(Exception) { Hash.new("nih:sha-256-32;5326-9067;b") }
    end

    it "should work with binary data" do
      hash_init = NamedInformation.generate_hash("Hello World!")

      # convert to binary data
      bin = hash_init.to_slice

      # convert back to a hash
      hash = Hash.new(bin)
      hash.should eq hash_init
    end

    it "should work with 128 UInts" do
      hash_init = NamedInformation.generate_hash(test_data, truncate: 120)

      # convert to integer
      int = hash_init.to_u128

      # convert back to a hash
      hash = Hash.new(int)
      hash.should eq hash_init
    end
  end
end
