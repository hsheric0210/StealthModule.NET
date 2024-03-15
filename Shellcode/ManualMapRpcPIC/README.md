# ManualMapRpcPIC - Remote-process DLL manual-mapping helper PIC

This is completely different from [sRDI (Shellcode Reflective DLL Injection)](https://github.com/monoxgas/sRDI) project.

To manual-map a DLL to a remote process, you need to execute certain function _at the target remote process_.

For example, you need to call the main entry point of the dll 'DllMain' from the target process, not from your injector process.

This PIC project does this job. The shellcode is loaded to your target remote process, establish a named-pipe connection between the injector and then do the requested job.

## Notice

The method that StealthModule.RemoteMemoryModule uses is a bit differ from [sRDI (Shellcode Reflective DLL Injection)](https://github.com/monoxgas/sRDI).

Check out StealthModule.RemoteMemoryModule for detailed explanation.

## Protocol and Supported Ops

### Error codes (returned by the entry function)

* MM_ERROR_NO_EXPORT (0x1) - Failed to resolve required exports.
* MM_ERROR_OPEN_PIPE (0x2) - Failed to open the named pipe.
* MM_ERROR_READ_PIPE (0x3) - Failed to read the named pipe.
* MM_ERROR_WRITE_PIPE (0x4) - Failed to write the named pipe.

### Packet OpCodes

* Query PEB Address (0x1)
* Check if the specified module is loaded (0x2)
* Load the specified DLL (0x3)
* Call the specified entry point function (TLS callback or DllMain) (0x4)
* Add function table (x64 exception table) (0x5)
* Terminate the RPC session (0x6)
* Unknown packet opcode (0xffff)
