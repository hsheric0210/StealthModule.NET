# ExportResolver

Drop-in replacement of `GetModuleHandle` and `GetProcAddress` Win32 API.

## Find and print the base address of `kernel32.dll`

Use `ExportResolver.GetModuleHandle` function.

```csharp
var address = ExportResolver.GetModuleHandle("kernel32.dll");
Console.WriteLine(address.ToString());
```

## Resolve the export address of `VirtualAlloc` and call it

There are multiple solutions.

## Utility usage

If you want to just resolve that one function, you can use `ExportResolver.ResolveExport` utility function.

```csharp
private delegate IntPtr VirtualAllocDelegate(IntPtr lpAddress, UIntPtr dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

private void Resolve_Address_Then_Call_Delegate()
{
    var pfnVirtualAlloc = ExportResolver.ResolveExports("kernel32.dll", "VirtualAlloc");
    var virtualAlloc = Marshal.GetDelegateForFunctionPointer<VirtualAllocDelegate>(pfnVirtualAlloc);
    var memory = virtualAlloc(IntPtr.Zero, (UIntPtr)1024, AllocationType.COMMIT | AllocationType.Reserved, MemoryProtection.READWRITE);
    ...
}

private void Direct_Get_Delegate()
{
    var virtualAlloc = (VirtualAllocDelegate)ExportResolver.ResolveExports("kernel32.dll", "VirtualAlloc", typeof(VirtualAllocDelegate));
    var memory = virtualAlloc(IntPtr.Zero, (UIntPtr)1024, AllocationType.COMMIT | AllocationType.Reserved, MemoryProtection.READWRITE);
    ...
}

private void Direct_Get_Delegate_Generic()
{
    var virtualAlloc = ExportResolver.ResolveExports<VirtualAllocDelegate>("kernel32.dll", "VirtualAlloc");
    var memory = virtualAlloc(IntPtr.Zero, (UIntPtr)1024, AllocationType.COMMIT | AllocationType.Reserved, MemoryProtection.READWRITE);
    ...
}
```

## Using ExportResolver itself

If you want to resolve multiple or batch exports, you can use `ExportResolver` type itself.

```csharp
private delegate IntPtr VirtualAllocDelegate(IntPtr lpAddress, UIntPtr dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

private void Resolve_Address_Then_Call_Delegate()
{
    var virtualAlloc = new ExportResolver("kernel32.dll").GetExport<VirtualAllocDelegate>("VirtualAlloc");
    var memory = virtualAlloc(IntPtr.Zero, (UIntPtr)1024, AllocationType.COMMIT | AllocationType.Reserved, MemoryProtection.READWRITE);
    ...
}
```

## Using Module Handle

You can even specify the Module Handle (also known as Module Base Address) instead of the module name.

The module handle can be resolved using Win32 API `GetModuleHandle` or `ExportResolver.GetModuleHandle`.

```csharp
private void Direct_Get_Delegate_Generic()
{
    var moduleHandle = ExportResolver.GetModuleHandle("kernel32.dll");
    var virtualAlloc = new ExportResolver(moduleHandle).GetExport<VirtualAllocDelegate>("VirtualAlloc");
    var memory = virtualAlloc(IntPtr.Zero, (UIntPtr)1024, AllocationType.COMMIT | AllocationType.Reserved, MemoryProtection.READWRITE);
    ...
}
```

## Using function ordinal

You can specify the function ordinal instead of the function name to choose export.


```csharp
private delegate IntPtr VirtualAllocDelegate(IntPtr lpAddress, UIntPtr dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

private void Direct_Get_Delegate_Generic()
{
    var virtualAlloc = ExportResolver.ResolveExports<VirtualAllocDelegate>("kernel32.dll", 0x05DA); // Windows 10 22H2; kernel32 version 6.2.19041.3636
    var memory = virtualAlloc(IntPtr.Zero, (UIntPtr)1024, AllocationType.COMMIT | AllocationType.Reserved, MemoryProtection.READWRITE);
    ...
}
```
