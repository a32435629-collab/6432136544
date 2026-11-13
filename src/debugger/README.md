# Debugger

`DebugModel.hpp` implements a framework-independent debugger session state model, breakpoint metadata, and a bounded event queue.

It does not attach to or control operating-system processes, read/write process memory, set native breakpoints, or execute debug events. A platform backend must be implemented separately.
