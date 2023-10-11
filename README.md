# named_information

A crystal lang implementation of [rfc6920](https://datatracker.ietf.org/doc/html/rfc6920)

## Installation

1. Add the dependency to your `shard.yml`:

   ```yaml
   dependencies:
     named_information:
       github: spider-gazelle/named_information
   ```

2. Run `shards install`

## Usage

basic usage

```crystal
require "named_information"

NamedInformation.generate_uri("Hello World!") #=> "ni:///sha-256;f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk"

hash = NamedInformation::Hash.new "ni://example.com/sha-256;f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk"
hash.matches?("Hello World!") # => true
hash.authority # => "example.com"
hash.algorithm # => "sha-256"

other_hash = NamedInformation::Hash.new "sha-256;f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk"

hash == other_hash # => true
```

Works with binary data

```crystal
require "named_information"

hash = Hash.new(bytes)
hash.to_slice

hash = Hash.new(uint128)
hash.to_u128
```

## Contributors

- [Stephen von Takach](https://github.com/stakach) - creator and maintainer
