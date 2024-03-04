# StealthModule.NET :: Load modules in-memory and invoke

<p align="center" style="text-align:center">
    <img alt="Logo image" src="logo.png">
</p>

This project is heavily based on [DllFromMemory.Net](https://github.com/schellingb/DLLFromMemory-net/) and [DInvoke](https://github.com/TheWover/DInvoke) project.

1. Extra indirection layer is added when calling native APIs.

2. No single P/Invoke usages. No `nameof()` usages. All strings are able to be obfuscated.

3. Feel free to edit `AssemblyInfo.cs` to change file name, description, version, etc.

## How to use

## How to reference this project from your project

### Solution 1 - git submodule

### Solution 2 - Manual DLL reference

## Contributions

DllFromMemory.Safer.NET is based on DllFromMemory.Net commit 7b1773c8035429e6fb1ab4b8fd0a52d2a4810efc.
https://github.com/schellingb/DLLFromMemory-net

DLLFromMemory.Net is based on Memory Module.net 0.2
Copyright (C) 2012 - 2018 by Andreas Kanzler
https://github.com/Scavanger/MemoryModule.net

Memory Module.net is based on Memory DLL loading code Version 0.0.4
Copyright (C) 2004 - 2015 by Joachim Bauch
https://github.com/fancycode/MemoryModule

## Related repositories

* [DllFromMemory.Net](https://github.com/schellingb/DLLFromMemory-net)
* [DInvoke](https://github.com/TheWover/DInvoke)

`Resolver.cs` is based on DInvoke [Generic.cs](https://github.com/TheWover/DInvoke/blob/15924897d9992ae90ec43aaf3b74915df3e4518b/DInvoke/DInvoke/DynamicInvoke/Generic.cs)

DLL Manual Mapping utility parts are based on DLLFromMemory-net [DLLFromMemory.cs](https://github.com/schellingb/DLLFromMemory-net/blob/7b1773c8035429e6fb1ab4b8fd0a52d2a4810efc/DLLFromMemory.cs#)
