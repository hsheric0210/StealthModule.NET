﻿using StealthModule;
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
            RunDLL(dllName, entryPoint);
        }

        private delegate void DllEntryPoint();

        private static void RunDLL(string dllName, string entryPoint)
        {
            var dllHandle = ExportResolver.GetModuleHandle(dllName);
            if (dllHandle == Pointer.Zero)
            {
                Console.WriteLine("  [+] The DLL file is already loaded into this process: " + dllName);
                ExecuteEntryPoint(entryPoint, ExportResolver.ResolveExport(dllHandle, entryPoint));
            }
            else
            {
                FindAndRunDLL(dllName, entryPoint);
            }
        }

        private static void ExecuteEntryPoint(string entryPointName, Pointer entryPoint)
        {
            if (entryPoint == Pointer.Zero)
            {
                Console.WriteLine("  [-] The entry point function " + entryPointName + " not found.");
                return;
            }

            Console.WriteLine("  [+] The entry point function " + entryPointName + " is at: " + entryPoint);

            try
            {
                var entry = Marshal.GetDelegateForFunctionPointer<DllEntryPoint>(entryPoint);
                entry();
                Console.WriteLine("  [+] The entry point call was successful.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("  [+] The entry point call failed with an exception: " + ex);
            }
        }

        private static void FindAndRunDLL(string dllName, string entryPointName)
        {
            if (!File.Exists(dllName))
            {
                Console.WriteLine("  [-] DLL file doesn't exist: " + dllName);
                return;
            }

            var dllBytes = File.ReadAllBytes(dllName);
            Console.WriteLine("  [+] Read " + dllBytes.Length + " bytes from the disk. Begin manual mapping...");

            var module = new MemoryModule(dllBytes);
            var entryPoint = module.GetExport(entryPointName);
            ExecuteEntryPoint(entryPointName, entryPoint);
        }

        private static void PrintSyntax()
        {
            Console.WriteLine("RunDll32 implemented in C# with StealthModule.NET");
            Console.WriteLine("This program will manual-map the specified dll, and then call the specified entry point function.");
            Console.WriteLine("NOTE: Unlike the original RunDLL32.exe included in Windows, the optional parameter feature is not implemented in this program.");
            Console.WriteLine("Syntax: RunDll32.exe dll_name,EntryPoint");
            Console.WriteLine("\t\tdll_name - The DLL file to run");
            Console.WriteLine("\t\tEntryPoint - The entry point function name");
        }
    }
}