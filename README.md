PE analyzer
===========

This repository contains a
[Spicy](https://docs.zeek.org/projects/spicy/en/latest/)-based analyzer for the
Portable Executable (PE) image file format,

- [PE format specification](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Tour of the Win32 Portable Executable File Format](https://docs.microsoft.com/en-us/previous-versions/ms809762(v=msdn.10))
- [Wikipedia: Portable Executable](https://en.wikipedia.org/wiki/Portable_Executable)

TODOs
-----

- parse the data from remaining directory sections
- allowing tuning/control of parsing contraints would be nice, but
  something that Spicy would have to support, see [this discussion](https://github.com/zeek/spicy/discussions/765)
