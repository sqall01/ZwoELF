ZwoELF
============

An ELF parsing and manipulation library for Python

Why is it named "ZwoELF" (German for "twelve")? Because ELF is German for "eleven" and I like to go one step further than others ;-)

This library works only with x86 and x86_64 ELF binaries. It was written as a parser library to understand the ELF format and gained some manipulation functions after a while. In contrast to most ELF analysis tools (for example "readelf"), I tried to use the information that the ELF loader uses to load the binary. As a result, the library ignores the "sections" of the binary in order to work even if the "sections" held wrong information.

It is not finished yet (due to time problems) nor the manipulation in any state of reliable use.


How to use it
============

I added some examples in the directory "examples" that will show how the library can be used.
