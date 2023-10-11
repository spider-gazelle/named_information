require "openssl"
require "base64"
require "uri"

# implementation of [rfc6920](https://datatracker.ietf.org/doc/html/rfc6920)
module NamedInformation
  {% begin %}
    VERSION = {{ `shards version "#{__DIR__}"`.chomp.stringify.downcase }}
  {% end %}

  ALGORITHM_ID = {
    "1" => {algorithm: "SHA256", truncate: nil.as(Int32?)},
    "2" => {algorithm: "SHA256", truncate: 128.as(Int32?)},
    "3" => {algorithm: "SHA256", truncate: 120.as(Int32?)},
    "4" => {algorithm: "SHA256", truncate: 96.as(Int32?)},
    "5" => {algorithm: "SHA256", truncate: 64.as(Int32?)},
    "6" => {algorithm: "SHA256", truncate: 32.as(Int32?)},
  }

  # Compute the Luhn check digit for a given number string
  def self.luhn_checkdigit(input : String, n : Int32 = 16) : Char
    factor = 2
    sum = 0

    # Starting from the right and working leftwards is easier since
    # the initial "factor" will always be "2"
    (input.size - 1).downto(0) do |i|
      code_point = code_point_from_character(input[i])
      addend = factor * code_point

      # Alternate the "factor" that each "codePoint" is multiplied by
      factor = (factor == 2) ? 1 : 2

      # Sum the digits of the "addend" as expressed in base "n"
      addend = (addend // n) + (addend % n)
      sum += addend
    end

    # Calculate the number that must be added to the "sum"
    # to make it divisible by "n"
    remainder = sum % n
    check_code_point = (n - remainder) % n

    character_from_code_point(check_code_point)
  end

  def self.code_point_from_character(char : Char) : Int32
    if '0' <= char <= '9'
      char.ord - '0'.ord
    elsif 'a' <= char
      char.ord - 'a'.ord + 10
    else
      raise "invalid character in hash: #{char}"
    end
  end

  def self.character_from_code_point(code_point : Int32) : Char
    if 0 <= code_point <= 9
      (code_point + '0'.ord).chr
    else
      (code_point - 10 + 'a'.ord).chr
    end
  end

  # Return hash of the content using the given algorithm, with optional truncation
  def self.hash_content(content : String | Bytes, algorithm : String, truncate : Int32? = nil)
    bytes = OpenSSL::Digest.new(algorithm).update(content).final
    truncate ? bytes[0...(truncate // 8)] : bytes
  end

  def self.algorithm_name(algorithm : String, truncate : Int32?) : String
    base_name = algorithm.downcase.gsub(/(\d+)/, "-\\1")
    return "#{base_name}-#{truncate}" if truncate
    base_name
  end

  def self.generate_uri(
    content : String | Bytes,
    authority : String? = nil,
    truncate : Int32? = nil,
    algorithm : String = "SHA256"
  ) : String
    hash_bytes = hash_content(content, algorithm, truncate)
    hash_base64 = Base64.urlsafe_encode(hash_bytes, padding: false)
    Hash.new(hash_base64, algorithm_name(algorithm, truncate), authority).to_uri
  end

  def self.generate_well_known(
    content : String | Bytes,
    authority : String? = nil,
    truncate : Int32? = nil,
    algorithm : String = "SHA256"
  ) : String
    hash_bytes = hash_content(content, algorithm, truncate)
    hash_base64 = Base64.urlsafe_encode(hash_bytes, padding: false)
    Hash.new(hash_base64, algorithm_name(algorithm, truncate), authority).to_well_known
  end

  def self.generate_segment(
    content : String | Bytes,
    truncate : Int32? = nil,
    algorithm : String = "SHA256"
  ) : String
    hash_bytes = hash_content(content, algorithm, truncate)
    hash_base64 = Base64.urlsafe_encode(hash_bytes, padding: false)
    Hash.new(hash_base64, algorithm_name(algorithm, truncate)).to_segment
  end

  def self.generate_hash(
    content : String | Bytes,
    authority : String? = nil,
    truncate : Int32? = nil,
    algorithm : String = "SHA256"
  ) : Hash
    hash_bytes = hash_content(content, algorithm, truncate)
    hash_base64 = Base64.urlsafe_encode(hash_bytes, padding: false)
    Hash.new(hash_base64, algorithm_name(algorithm, truncate), authority)
  end

  def self.generate_bin(
    content : String | Bytes,
    truncate : Int32? = nil,
    algorithm : String = "SHA256"
  ) : BinHash
    hash_bytes = hash_content(content, algorithm, truncate)
    hash_base64 = Base64.urlsafe_encode(hash_bytes, padding: false)
    Hash.new(hash_base64, algorithm_name(algorithm, truncate)).to_bin
  end

  def self.generate_u128(content : String | Bytes) : UInt128
    hash_bytes = hash_content(content, "SHA256", 120)
    hash_base64 = Base64.urlsafe_encode(hash_bytes, padding: false)
    bin = Hash.new(hash_base64, algorithm_name(algorithm, truncate)).to_bin
    io = IO::Memory.new
    io.write_bytes(bin)
    io.pos = 0
    io.read_bytes(UInt128)
  end

  def self.generate_human_speakable(
    content : String | Bytes,
    truncate : Int32? = nil,
    algorithm : String | Int32 = "SHA256",
    checkdigit : Bool = true
  ) : String
    case algorithm
    in Int32
      algorithm_name = algorithm.to_s
      hash_bytes = hash_content(content, **ALGORITHM_ID[algorithm_name])
    in String
      algorithm_name = algorithm_name(algorithm, truncate)
      hash_bytes = hash_content(content, algorithm, truncate)
    end

    convert_to_human_speakable(hash_bytes, algorithm_name, checkdigit)
  end

  def self.convert_to_human_speakable(hash : Bytes, algorithm_name : String, checkdigit : Bool) : String
    # Group the hex representation for better readability
    hex_representation = hash.hexstring
    grouped_hash = hex_representation.chars.each_slice(4).map(&.join).join("-")

    return "nih:#{algorithm_name};#{grouped_hash};#{luhn_checkdigit(hex_representation)}" if checkdigit
    "nih:#{algorithm_name};#{grouped_hash}"
  end
end

require "./named_information/*"
