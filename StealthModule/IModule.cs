using System;

namespace StealthModule
{
    public interface IModule : IDisposable
    {
        ExportResolver Exports { get; }
        Pointer BaseAddress { get; }
    }
}