# MemoryModule

Load a valid EXE or DLL portable executable file in-memory on-the-fly.

Don't forget to dispose MemoryModule class after use! Otherwise it will create a memory leak.

Also, you should be careful that when the MemoryModule instance is Garbage Collected, all associated memory regions are freed, thus resulting in all export function delegate becomes invalid pointer. (It will raise AccessViolationException when you access these export function delegates)

## Manual map a DLL file and call `MyExportFunction1` export function

```csharp
private delegate IntPtr MyExportDelegate(string myParameter);

public void ManualMap(byte[] dllBytes)
{
    using (var module = new MemoryModule(dllBytes)) // Auto-dispose
    {
        var myExport = module.GetExport<MyExportDelegate>("MyExportFunction1");
        myExport("Hello, World!");
    }
}
```

## Manual map a DLL, find all necessary exports, then purge the DLL header

```csharp
private delegate IntPtr MyExportDelegate(string myParameter);
private delegate IntPtr Job1Delegate(int param1, long param2, string param3);
private delegate IntPtr Job2Delegate(short param1, char param2, byte param3);

public void ManualMap(byte[] dllBytes)
{
    using (var module = new MemoryModule(dllBytes)) // Auto-dispose
    {
        var myExport = module.GetExport<MyExportDelegate>("MyExportFunction1");
        var job1 = module.GetExport<Job1Delegate>("MyJob1");
        var job2 = module.GetExport<Job2Delegate>("MyJob2");

        module.EraseHeaders();

        myExport("Hello, World!");
        job1(1234, 5678L, "9 10 11 12");
        job2(1337, 'W', 0xFF);

        ...
    }
}
```
