# DotLocalPreload
Preloads on Windows using DotLocal debugging

## Background

Dynamic linkers on POSIX have a very helpful environment variable
called ``LD_PRELOAD`` which can be used to hook functions very easily.

Windows has no such environment variable but it has a certain
[DLL search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
that can be used to put DLL in a location that can be loaded
before other DLLs are loaded.

They have maintained the search order over the years to better
prevent programs like user-mode rootkits from installing important
"known" DLLs in certain locations to make programs do what they were
not supposed to do. If a "safe search" order is applied, DLLs in
``System32`` are also loaded earlier.

However, for developers, a handy trick called
[.local debugging](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-redirection)
is used to load even before any system ``DLLs``.

This program takes advantage of ``.local debugging`` by taking a
reference and preload DLL and dynamically creating a forwarder DLL
that [proxies](https://www.netspi.com/blog/technical/adversary-simulation/adaptive-dll-hijacking/#h-function-proxying) between the two DLLs.

## Building
```
cd Windows
cl dlp.c
```

## Usage
```
Usage: dlp.exe PreloadDLL ReferenceDLL
```

``dlp.exe`` exports all the exports from ``ReferenceDLL``
and only those exports. Then, if one of the exports is
defined in ``PreloadDLL``, it will forward the export
to ``PreloadDLL`` instead of ``ReferenceDLL``.

## TODO

* There's a lot of PE parsing. Consider writing a fuzzer.
* Output a DEF file instead on request.
* Export by ordinals only are unimplemented!
* ``dlp.c`` does not compile with other compilers besides MSVC!
  - Test ``mingw gcc``
  - Test ``clang``
  - Test ``tcc``
