using System;

namespace StealthModule
{
    /// <summary>
    /// Codes in this class are copied from DInvoke project:
    /// https://github.com/TheWover/DInvoke
    /// </summary>
    public partial class ExportResolver
    {
        public static Pointer ResolveExport(Pointer moduleBase, string exportName)
            => new ExportResolver(moduleBase).GetExport(exportName);

        public static Pointer ResolveExport(string moduleName, string exportName)
            => new ExportResolver(moduleName).GetExport(exportName);

        public static Delegate ResolveExport(Pointer moduleBase, string exportName, Type delegateType)
            => new ExportResolver(moduleBase).GetExport(exportName, delegateType);

        public static Delegate ResolveExport(string moduleName, string exportName, Type delegateType)
            => new ExportResolver(moduleName).GetExport(exportName, delegateType);

#if NET451_OR_GREATER
        public static TDelegate ResolveExport<TDelegate>(Pointer moduleBase, string exportName)
            => new ExportResolver(moduleBase).GetExport<TDelegate>(exportName);

        public static TDelegate ResolveExport<TDelegate>(string moduleName, string exportName)
            => new ExportResolver(moduleName).GetExport<TDelegate>(exportName);
#endif

        public static Pointer ResolveExport(Pointer moduleBase, short exportOrdinal)
            => new ExportResolver(moduleBase).GetExport(exportOrdinal);

        public static Pointer ResolveExport(string moduleName, short exportOrdinal)
            => new ExportResolver(moduleName).GetExport(exportOrdinal);

        public static Delegate ResolveExport(Pointer moduleBase, short exportOrdinal, Type delegateType)
            => new ExportResolver(moduleBase).GetExport(exportOrdinal, delegateType);

        public static Delegate ResolveExport(string moduleName, short exportOrdinal, Type delegateType)
            => new ExportResolver(moduleName).GetExport(exportOrdinal, delegateType);

#if NET451_OR_GREATER
        public static TDelegate ResolveExport<TDelegate>(Pointer moduleBase, short exportOrdinal)
            => new ExportResolver(moduleBase).GetExport<TDelegate>(exportOrdinal);

        public static TDelegate ResolveExport<TDelegate>(string moduleName, short exportOrdinal)
            => new ExportResolver(moduleName).GetExport<TDelegate>(exportOrdinal);
#endif
    }
}