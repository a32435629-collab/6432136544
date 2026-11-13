# Compression

Header-only bounded RLE codec in `Compression.hpp`. The format is a small internal PackBits-like encoding, not ZIP, gzip, zlib, LZ4, or a general archive reader.

- `encodeRle` encodes byte spans.
- `decodeRle` validates truncated streams and enforces a configurable output limit.
- No filesystem or network access is performed.
