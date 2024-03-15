# ManualMapRpcPIC - Remote-process DLL manual-mapping helper PIC

This is completely different from [sRDI (Shellcode Reflective DLL Injection)](https://github.com/monoxgas/sRDI) project.

To manual-map a DLL to a remote process, you need to execute certain function _at the target remote process_.

For example, you need to call the main entry point of the dll 'DllMain' from the target process, not from your injector process.

This PIC project does this job. The shellcode is loaded to your target remote process, establish a named-pipe connection between the injector and then do the requested job.

## Notice

The method that StealthModule.RemoteMemoryModule uses is a bit differ from [sRDI (Shellcode Reflective DLL Injection)](https://github.com/monoxgas/sRDI).

Check out StealthModule.RemoteMemoryModule for detailed explanation.
