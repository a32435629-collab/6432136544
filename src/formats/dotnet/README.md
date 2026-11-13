# .NET / CLR parser

Parses managed PE32 and PE32+ files, maps the CLR data directory through PE
sections, validates IMAGE_COR20_HEADER, and parses the BSJB metadata root.

The result exposes CLR runtime version, flags, entry-point token, metadata version,
metadata stream directory, and valid metadata table IDs with row counts. Streams
such as #~, #- , #Strings, #US, #GUID and #Blob are enumerated and bounds-checked.

Example:
~~~cpp
#include "formats/dotnet/DotNetParser.hpp"
auto result = lulz::dotnet::parse(fileBytes);
if (result) {
    const auto& image = result.value();
    // image.metadataVersion, image.streams, image.tables
}
~~~

Limitations: table rows and assembly identity are not decoded yet. IL bodies,
signatures, resources, strong-name cryptography, ReadyToRun and mixed-mode native
code are not interpreted. Native PE files without a CLR directory are rejected.
