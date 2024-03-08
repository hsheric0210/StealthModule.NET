using StealthModule;
using System;
using System.IO;
using System.Runtime.InteropServices;

namespace RunDll32
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

            var pieces = args[0].Split(',');
            if (pieces.Length != 2)
            {
                PrintSyntax();
                return;
            }

            var dllName = pieces[0];
            var entryPoint = pieces[1];
            if (dllName.Length <= 0 || entryPoint.Length <= 0)
            {
                PrintSyntax();
                return;
            }

            RunDLL(dllName, entryPoint);
        }

        private delegate void DllEntryPoint();

        private static void RunDLL(string dllName, string entryPointName)
        {
            if (!File.Exists(dllName))
            {
                Console.WriteLine("[-] DLL file doesn't exist: " + dllName);
                return;
            }

            var dllBytes = File.ReadAllBytes(dllName);
            Console.WriteLine("[+] Read " + dllBytes.Length + " bytes from the disk. Begin manual mapping...");

            var module = new MemoryModule(dllBytes);

            var entryPoint = entryPointName[0] == '#' ? module.Exports[int.Parse(entryPointName.Substring(1))] : module.Exports[entryPointName];
            if (entryPoint == Pointer.Zero)
            {
                Console.WriteLine("[-] The entry point function " + entryPointName + " not found.");
                return;
            }

            Console.WriteLine("[+] The entry point function " + entryPointName + " is at: " + entryPoint);

            try
            {
                var entry = Marshal.GetDelegateForFunctionPointer<DllEntryPoint>(entryPoint);
                entry();
                Console.WriteLine("[+] The entry point call was successful.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[+] The entry point call failed with an exception: " + ex);
            }
        }

        private static void PrintSyntax()
        {
            Console.WriteLine("RunDll32 implemented in C# with StealthModule.NET");
            Console.WriteLine("This program will manual-map the specified dll, and then call the specified entry point function.");
            Console.WriteLine("Warning: Optional parameters are unsupported.");
            Console.WriteLine("Syntax: RunDll32.exe dll_name,EntryPoint");
            Console.WriteLine("\tdll_name - The DLL file to run");
            Console.WriteLine("\tEntryPoint - The entry point function name or ordinal (to use ordinal the '#' prefix must be appended)");
            Console.WriteLine("");
            Console.WriteLine("'Rundll32.exe abcd.dll,foobarbaz123' - Call the abcd.dll's 'foobarbaz123' exported function");
            Console.WriteLine("'Rundll32.exe efgh.dll,#1' - Call the efgh.dll's export function with ordinal 1");
        }
    }
}
