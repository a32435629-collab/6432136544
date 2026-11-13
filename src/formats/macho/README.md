# Mach-O format parser

This directory contains the thin Mach-O parser for 32-bit and 64-bit images.

## Implemented

- Validates little-endian and big-endian Mach-O magic values.
- Parses the Mach header and validates the complete load-command region.
- Parses 32-bit `LC_SEGMENT` and 64-bit `LC_SEGMENT_64` commands and their sections.
- Extracts linked dynamic library names from dylib load commands.
- Reads the `LC_MAIN` entry-point file offset.
- Rejects truncated, malformed, and out-of-bounds structures with `lulz::Result`.

## API

Include `formats/macho/MachOParser.hpp` and call:

```cpp
auto image = lulz::macho::parse(bytes);
if (!image) {
    // image.error() contains the validation error
}
```

Fat/universal containers are not parsed by this module yet. Select a slice before passing bytes to this parser.
