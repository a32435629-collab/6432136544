# Database

`AnalysisStore.hpp` provides a header-only in-memory artifact metadata store with insert/upsert/find/delete, sorted listing, and tag filtering.

This is an in-process data model, not SQLite or durable storage. Persistence, migrations, concurrent access, and schema versioning are not implemented.
