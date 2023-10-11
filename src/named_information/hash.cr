require "json"

struct NamedInformation::Hash
  include JSON::Serializable

  def initialize(ni : String)
    if ni.starts_with? "ni:"
      uri = URI.parse ni
      @authority = uri.host
      @algorithm, @hash = uri.path[1..-1].split(';', 2)
    elsif ni.starts_with? "nih:"
      parts = ni[4..-1].split(';')
      alg, hex_hash = parts
      if alg.size == 1
        @algorithm = NamedInformation.algorithm_name(**ALGORITHM_ID[alg])
      else
        @algorithm = alg
      end

      # remove optional dashes
      check_hex_hash = hex_hash.gsub('-', "")
      # ensure correct size
      hex_hash = check_hex_hash.size % 2 == 0 ? check_hex_hash : "0#{check_hex_hash}"
      @hash = Base64.urlsafe_encode(hex_hash.hexbytes, padding: false)

      if checkdigit = parts[2]?
        raise "invalid hash, check digit mismatch" unless checkdigit[0] == NamedInformation.luhn_checkdigit(check_hex_hash)
      end
    elsif ni.includes? ".well-known"
      uri = URI.parse ni
      @authority = uri.host
      path = uri.path.split('/')
      @algorithm = path[3]
      @hash = path[4]
    else # assume it's a segment
      @algorithm, @hash = ni.split(';')
    end
  end

  def initialize(ni : URI)
    if ni.scheme == "ni"
      @authority = ni.host
      @algorithm, @hash = ni.path[1..-1].split(';', 2)
    else # assumes ".well-known"
      @authority = ni.host
      path = ni.path.split('/')
      @algorithm = path[3]
      @hash = path[4]
    end
  end

  def self.new(bytes : Bytes)
    io = IO::Memory.new(bytes)
    io.read_bytes(BinHash).to_hash
  end

  def self.new(integer : UInt128)
    io = IO::Memory.new
    io.write_bytes(integer, IO::ByteFormat::NetworkEndian)
    io.pos = 0
    io.read_bytes(BinHash).to_hash
  end

  def initialize(@hash : String, @algorithm : String, @authority : String? = nil)
  end

  getter hash : String
  getter algorithm : String
  getter authority : String? = nil

  # we don't require authority to have two hashes match
  def_equals @algorithm, @hash

  def params : NamedTuple(algorithm: String, truncate: Int32?)
    # supports both sha-256 and sha256
    parts = algorithm.split('-')
    alg = parts[0]
    if alg =~ /^[a-z]+$/
      alg = "#{alg}#{parts[1]}"
      truncate = parts[2]?
    else
      truncate = parts[1]?
    end

    {algorithm: alg.upcase, truncate: truncate.try(&.to_i)}
  end

  def matches?(content : String | Bytes, authority : String? = nil) : Bool
    hash = NamedInformation.generate_hash(
      content,
      authority,
      **params
    )
    self == hash
  end

  def to_uri
    "ni://#{authority}/#{algorithm};#{hash}"
  end

  def to_s
    to_uri
  end

  def to_well_known
    "http://#{authority}/.well-known/ni/#{algorithm}/#{hash}"
  end

  def to_segment
    "#{algorithm};#{hash}"
  end

  def to_human_speakable(checkdigit : Bool = true)
    bytes = Base64.decode hash
    NamedInformation.convert_to_human_speakable(bytes, algorithm, checkdigit)
  end

  def to_bin
    bin = NamedInformation::BinHash.new
    id = case algorithm
         when "sha-256"     then 1_u8
         when "sha-256-128" then 2_u8
         when "sha-256-120" then 3_u8
         when "sha-256-96"  then 4_u8
         when "sha-256-64"  then 5_u8
         when "sha-256-32"  then 6_u8
         else
           raise "algorithm not supported in binary format: #{algorithm}"
         end
    bin.suite_id = id
    bin.hash_value = Base64.decode(hash)
    bin
  end

  def to_u128 : UInt128
    raise "only algorithm sha-256-120 supported, given: #{algorithm}" unless algorithm == "sha-256-120"
    to_bin.to_u128
  end

  def to_slice : Bytes
    to_bin.to_slice
  end
end
