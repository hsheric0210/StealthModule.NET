# MemoryModule

Load a valid EXE or DLL portable executable file in-memory on-the-fly.

Don't forget to dispose MemoryModule class after use! Otherwise it will create a memory leak.

Also, you should be careful that when the MemoryModule instance is Garbage Collected, all associated memory regions are freed, thus resulting in all export function delegate becomes invalid pointer. (It will raise AccessViolationException when you access these export function delegates)

## Manual map a DLL file and call `MyExportFunction1` export function

```csharp
private delegate IntPtr MyExportDelegate(string myParameter);

public void InitNative(byte[] dllBytes)
{
    using (var module = new MemoryModule(dllBytes)) // Auto-dispose
    {
        var myExport = module.GetExport<MyExportDelegate>("MyExportFunction1");
        myExport("Hello, World!");
    }
}
```
