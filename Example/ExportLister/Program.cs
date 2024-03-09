using StealthModule;
using System;
using System.IO;

namespace ExportLister
{
    internal class Program
    {
        static void Main(string[] args)
        {
            if (args.Length != 1)
            {
                PrintSyntax();
                return;
            }

            var dllName = args[0];
            var moduleHandle = ExportResolver.GetModuleHandle(dllName);
            ExportResolver resolver;
            MemoryModule mapped = null;
            if (moduleHandle == Pointer.Zero)
            {
                if (!File.Exists(dllName))
                {
                    Console.WriteLine("[-] The dll file not found.");
                    return;
                }

                Console.WriteLine("[+] Begin dll manual mapping...");

                var bytes = File.ReadAllBytes(dllName);
                Console.WriteLine($"[+] Read {bytes.Length} bytes from the disk.");

                mapped = new MemoryModule(bytes);
                moduleHandle = mapped.BaseAddress;
                resolver = mapped.Exports;

                Console.WriteLine($"[+] The DLL is manual mapped to {moduleHandle}");
            }
            else
            {
                Console.WriteLine($"[+] The specified dll has found from the loaded module list: {moduleHandle}");
                resolver = new ExportResolver(moduleHandle);
            }

            resolver.WalkEDT(export =>
            {
                Console.WriteLine($"[+] 0x{export.FunctionAddress} (0x{export.FunctionAddress - moduleHandle}) - #{export.FunctionOrdinal} {export.FunctionName}");
                return false; // continue
            });

            if (mapped != null)
            {
                Console.WriteLine("[+] Disposing the manual mapped DLL.");
                mapped.Dispose(true); // prevent DllMain with DLL_PROCSES_DETACH call because some DLLs might crash from this stage
            }
        }

        private static void PrintSyntax()
        {
            Console.WriteLine("ExportLister lists all export function names, ordinals and addresses for the specified DLL.");
            Console.WriteLine("Syntax: ExportLister.exe dll_name");
            Console.WriteLine("\tdll_name - The DLL file path");
        }
    }
}
