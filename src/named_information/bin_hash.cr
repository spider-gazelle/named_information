require "bindata"

class NamedInformation::BinHash < BinData
  endian network

  bit_field do
    # Res field is a reserved 2-bit field for future use
    bits 2, :reserved

    # The hash algorithm and truncation length are specified by the Suite ID
    bits 6, :suite_id
  end

  field hash_value : Bytes, length: ->{
    bits = ALGORITHM_ID[suite_id.to_s][:truncate] || 256
    bits // 8
  }

  def hash
    Base64.urlsafe_encode(hash_value, padding: false)
  end

  def algorithm
    NamedInformation.algorithm_name(**ALGORITHM_ID[suite_id.to_s])
  end

  def to_hash
    Hash.new(hash, algorithm)
  end

  def to_u128 : UInt128
    raise "only algorithm sha-256-120 supported, given: #{algorithm}" unless suite_id == 3_u8
    io = IO::Memory.new
    io.write_bytes(self)
    io.pos = 0
    io.read_bytes(UInt128, IO::ByteFormat::NetworkEndian)
  end
end
