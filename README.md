PE analyzer
===========

This repository contains a
[Spicy](https://docs.zeek.org/projects/spicy/en/latest/)-based analyzer for the
Portable Executable (PE) image file format,

- [PE format specification](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Tour of the Win32 Portable Executable File Format](https://docs.microsoft.com/en-us/previous-versions/ms809762(v=msdn.10))
- [Wikipedia: Portable Executable](https://en.wikipedia.org/wiki/Portable_Executable)

This analyzer replaces the builtin Zeek PE analyzer.

Options
-----

Some fields in the logs are disabled by default, but they can be enabled with the following redefinitions.

| Option | Description  |
|---|---|
| `PE::pe_log_section_entropy=T`  | Log the Shannon entropy for every section in the `section_names` field. |
| `PE::pe_log_section_flags=T` | Log whether sections are (**r**)eadable, (**e**)xecutable and/or (**w**)ritable in the `section_names` field. |
| `PE::pe_log_import_table=T` | Log all the imported function names in the PE, prepended with the source file, to the `import_table` field.  |
| `PE::pe_log_export_table=T`| Log all the exported function names in the PE to the `export_table` field. |

TODOs
-----

- parse the data from remaining directory sections
- allowing tuning/control of parsing contraints would be nice, but
  something that Spicy would have to support, see [this discussion](https://github.com/zeek/spicy/discussions/765)
