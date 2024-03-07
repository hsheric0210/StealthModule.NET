using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace StealthModule
{
    /// <summary>
    /// Codes in this class are copied from DInvoke project:
    /// https://github.com/TheWover/DInvoke
    /// </summary>
    public static class ExportResolver
    {
        /// <summary>
        /// Helper for getting the base address of a module loaded by the current process. This base
        /// address could be passed to GetProcAddress/LdrGetProcedureAddress or it could be used for
        /// manual export parsing. This function uses the .NET System.Diagnostics.Process class.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="moduleName">The name of the DLL (e.g. "ntdll.dll").</param>
        /// <param name="throwIfNotFound">Throw the <c>DLLException</c> when the specified DLL is not found from loaded module list.</param>
        /// <returns>IntPtr base address of the loaded module or IntPtr.Zero if the module is not found.</returns>
        /// <exception cref="ModuleException">Thrown when <paramref name="throwIfNotFound"/> is <c>true</c> and the specified <paramref name="moduleName"/> is not found from loaded module list.</exception>
        public static Pointer GetModuleHandle(string moduleName, bool throwIfNotFound = false)
        {
            var nameLower = moduleName.ToLower();
            foreach (ProcessModule module in Process.GetCurrentProcess().Modules)
            {
                if (module.FileName.ToLower().EndsWith(nameLower))
                    return module.BaseAddress;
            }

            if (throwIfNotFound)
                throw new ModuleException("Module not found: " + moduleName);

            return Pointer.Zero;
        }

        /// <summary>
        /// Given a module base address, resolve the address of a list of functions by manually walking the module export table.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="moduleBase">A pointer to the base address where the module is loaded in the current process.</param>
        /// <param name="exportNames">The name list of the exports to search for (e.g. <c>new string[]{"NtAlertResumeThread"}</c>).</param>
        /// <param name="throwIfNotFound">Throw the <c>DLLException</c> when any of the exports are not found from the specified module.</param>
        /// <returns>IntPtr for the desired function.</returns>
        /// <exception cref="ModuleException">Thrown when <paramref name="throwIfNotFound"/> is <c>true</c> and any of the specified exports are not found from the specified module <paramref name="moduleBase"/>.</exception>
        public static Pointer[] ResolveExports(Pointer moduleBase, string[] exportNames, bool throwIfNotFound = false)
        {
            var functionPtrs = new Pointer[exportNames.Length];
            try
            {
                // Traverse the PE header in memory
                var ntHeaders = Marshal.ReadInt32(moduleBase + 0x3C);
                var optionalHeader = moduleBase + ntHeaders + 0x18;
                var optionalHeaderMagic = Marshal.ReadInt16(optionalHeader);

                Pointer edtAddress;
                if (optionalHeaderMagic == 0x010b) // NT64
                    edtAddress = optionalHeader + 0x60;
                else
                    edtAddress = optionalHeader + 0x70;

                // Read -> IMAGE_EXPORT_DIRECTORY
                var edtRVA = Marshal.ReadInt32(edtAddress);
                var ordinalBase = Marshal.ReadInt32(moduleBase + edtRVA + 0x10);
                var numberOfNames = Marshal.ReadInt32(moduleBase + edtRVA + 0x18);
                var functionsRVA = Marshal.ReadInt32(moduleBase + edtRVA + 0x1C);
                var namesRVA = Marshal.ReadInt32(moduleBase + edtRVA + 0x20);
                var ordinalsRVA = Marshal.ReadInt32(moduleBase + edtRVA + 0x24);

                // Loop the array of export name RVA's
                for (var i = 0; i < numberOfNames; i++)
                {
                    var FunctionName = Marshal.PtrToStringAnsi(moduleBase + Marshal.ReadInt32(moduleBase + namesRVA + i * 4));
                    for (var j = 0; j < exportNames.Length; j++)
                    {
                        if (FunctionName.Equals(exportNames[j], StringComparison.OrdinalIgnoreCase))
                        {
                            var FunctionOrdinal = Marshal.ReadInt16(moduleBase + ordinalsRVA + i * 2) + ordinalBase;
                            var FunctionRVA = Marshal.ReadInt32(moduleBase + functionsRVA + 4 * (FunctionOrdinal - ordinalBase));
                            functionPtrs[j] = (long)moduleBase + FunctionRVA;
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
                    if (functionPtrs[i] == Pointer.Zero)
                        throw new ModuleException("Address for function " + exportNames[i] + " not found.");
                }
            }

            return functionPtrs;
        }

        public static Pointer[] ResolveExports(string moduleName, string[] exportNames, bool throwIfNotFound = false)
        {
            var moduleHandle = GetModuleHandle(moduleName, throwIfNotFound);
            if (moduleHandle == Pointer.Zero)
                return new Pointer[exportNames.Length];

            return ResolveExports(moduleHandle, exportNames, throwIfNotFound);
        }

        public static Pointer ResolveExport(Pointer moduleBase, string exportName)
            => ResolveExports(moduleBase, new string[] { exportName })[0];

        public static Pointer ResolveExport(string moduleName, string exportName, bool throwIfNotFound = false)
        {
            var moduleHandle = GetModuleHandle(moduleName, throwIfNotFound);
            if (moduleHandle == Pointer.Zero)
                return Pointer.Zero;

            return ResolveExport(moduleHandle, exportName);
        }
    }
}