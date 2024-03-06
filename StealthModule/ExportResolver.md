# ExportResolver

Drop-in replacement of `GetModuleHandle` and `GetProcAddress` Win32 API.

## Find and print the base address of `kernel32.dll`

Use `ExportResolver.GetModuleHandle` function.

```csharp
var address = ExportResolver.GetModuleHandle("kernel32.dll");
Console.WriteLine(address.ToString());
```

## Resolve the export address of `VirtualAlloc` and call it

Use `ExportResolver.ResolveExport` function.

```csharp
private delegate IntPtr DVirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

private void MyFunction()
{
    var pfnVirtualAlloc = ExportResolver.ResolveExports("kernel32.dll", "VirtualAlloc");
    var virtualAlloc = Marshal.GetDelegateForFunctionPointer<DVirtualAlloc>(pfnVirtualAlloc);
    var memory = virtualAlloc(IntPtr.Zero, (UIntPtr)1024, AllocationType.COMMIT | AllocationType.Reserved, MemoryProtection.READWRITE);

    ...
}
```

## Resolve multiple export addresses at once

Use `ExportResolver.ResolveExports` function.

```csharp
internal static void InitNatives()
{
    var exports = new string[] {
            "LoadLibraryA",
            "FreeLibrary",
            "VirtualAlloc",
            "VirtualFree",
            "VirtualProtect",
            "GetNativeSystemInfo",
            "GetProcAddress",
    };

    var addresses = ExportResolver.ResolveExports("kernel32.dll", exports, true);
    loadLibrary = Marshal.GetDelegateForFunctionPointer<DLoadLibrary>(addresses[0]);
    freeLibrary = Marshal.GetDelegateForFunctionPointer<DFreeLibrary>(addresses[1]);
    virtualAlloc = Marshal.GetDelegateForFunctionPointer<DVirtualAlloc>(addresses[2]);
    virtualFree = Marshal.GetDelegateForFunctionPointer<DVirtualFree>(addresses[3]);
    virtualProtect = Marshal.GetDelegateForFunctionPointer<DVirtualProtect>(addresses[4]);
    getNativeSystemInfo = Marshal.GetDelegateForFunctionPointer<DGetNativeSystemInfo>(addresses[5]);
    getProcAddress = Marshal.GetDelegateForFunctionPointer<DGetProcAddress>(addresses[6]);

    ...
}
```