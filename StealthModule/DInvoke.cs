﻿using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace StealthModule
{
    /// <summary>
    /// Codes in this class are copied from DInvoke project:
    /// https://github.com/TheWover/DInvoke
    /// </summary>
    public class DInvoke
    {
        /// <summary>
        /// Helper for getting the base address of a module loaded by the current process. This base
        /// address could be passed to GetProcAddress/LdrGetProcedureAddress or it could be used for
        /// manual export parsing. This function uses the .NET System.Diagnostics.Process class.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="dllName">The name of the DLL (e.g. "ntdll.dll").</param>
        /// <param name="throwIfNotFound">Throw the <c>DLLException</c> when the specified DLL is not found from loaded module list.</param>
        /// <returns>IntPtr base address of the loaded module or IntPtr.Zero if the module is not found.</returns>
        /// <exception cref="ModuleException">Thrown when <paramref name="throwIfNotFound"/> is <c>true</c> and the specified <paramref name="dllName"/> is not found from loaded module list.</exception>
        public static IntPtr GetModuleHandle(string dllName, bool throwIfNotFound = false)
        {
            var nameLower = dllName.ToLower();
            foreach (ProcessModule module in Process.GetCurrentProcess().Modules)
            {
                if (module.FileName.ToLower().EndsWith(nameLower))
                    return module.BaseAddress;
            }

            if (throwIfNotFound)
                throw new ModuleException("Module not found: " + dllName);

            return IntPtr.Zero;
        }

        /// <summary>
        /// Given a module base address, resolve the address of a list of functions by manually walking the module export table.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="moduleBase">A pointer to the base address where the module is loaded in the current process.</param>
        /// <param name="ExportNames">The name list of the exports to search for (e.g. <c>new string[]{"NtAlertResumeThread"}</c>).</param>
        /// <param name="throwIfNotFound">Throw the <c>DLLException</c> when any of the exports are not found from the specified module.</param>
        /// <returns>IntPtr for the desired function.</returns>
        /// <exception cref="ModuleException">Thrown when <paramref name="throwIfNotFound"/> is <c>true</c> and any of the specified exports are not found from the specified module <paramref name="moduleBase"/>.</exception>
        public static IntPtr[] GetProcAddressBatch(IntPtr moduleBase, string[] ExportNames, bool throwIfNotFound = false)
        {
            var functionPtrs = new IntPtr[ExportNames.Length];
            try
            {
                // Traverse the PE header in memory
                var PeHeader = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + 0x3C));
                var OptHeaderSize = Marshal.ReadInt16((IntPtr)(moduleBase.ToInt64() + PeHeader + 0x14));
                var OptHeader = moduleBase.ToInt64() + PeHeader + 0x18;
                var Magic = Marshal.ReadInt16((IntPtr)OptHeader);
                long pExport = 0;
                if (Magic == 0x010b) // NT64
                    pExport = OptHeader + 0x60;
                else
                    pExport = OptHeader + 0x70;

                // Read -> IMAGE_EXPORT_DIRECTORY
                var ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
                var OrdinalBase = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + ExportRVA + 0x10));
                //var NumberOfFunctions = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + ExportRVA + 0x14));
                var NumberOfNames = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + ExportRVA + 0x18));
                var FunctionsRVA = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + ExportRVA + 0x1C));
                var NamesRVA = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + ExportRVA + 0x20));
                var OrdinalsRVA = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + ExportRVA + 0x24));

                // Loop the array of export name RVA's
                for (var i = 0; i < NumberOfNames; i++)
                {
                    var FunctionName = Marshal.PtrToStringAnsi((IntPtr)(moduleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + NamesRVA + i * 4))));
                    for (var j = 0; j < ExportNames.Length; j++)
                    {
                        if (FunctionName.Equals(ExportNames[j], StringComparison.OrdinalIgnoreCase))
                        {
                            var FunctionOrdinal = Marshal.ReadInt16((IntPtr)(moduleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                            var FunctionRVA = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                            functionPtrs[j] = (IntPtr)((long)moduleBase + FunctionRVA);
                        }
                    }
                }
            }
            catch
            {
                // Catch parser failure
                throw new ModuleException("Failed to parse module exports.");
            }

            if (throwIfNotFound)
            {
                for (var i = 0; i < functionPtrs.Length; i++)
                {
                    if (functionPtrs[i] == IntPtr.Zero)
                        throw new ModuleException("Address for function " + ExportNames[i] + " not found.");
                }
            }

            return functionPtrs;
        }

        public static IntPtr GetProcAddress(IntPtr ModuleBase, string ExportName)
            => GetProcAddressBatch(ModuleBase, new string[] { ExportName })[0];
    }
}