# PEHeader

Parse the PE file and retrieve its header information.

```csharp
var header = PEHeader.GetFromFile("test.dll");
_ = header.NtHeadersSignature; // IMAGE_NT_HEADERS signature
_ = header.Is64Bit; // Is this file a 64-bit PE?
_ = header.FileHeader; // ImageFileHeader (IMAGE_FILE_HEADER)
_ = header.OptionalHeader; // ImageOptionalHeader (IMAGE_OPTIONAL_HEADER)
_ = header.Sections; // ImageSectionHeader[] (IMAGE_SECTION_HEADER[])
```

You can also retrieve it from managed or unmanaged byte array.

```csharp
byte[] dllBytes = ...;
var header = PEHeader.GetFromBytes(dllBytes);
```

```csharp
IntPtr nativeDllBytes = ...;
var header = new PEHeader(nativeDllBytes);
```
