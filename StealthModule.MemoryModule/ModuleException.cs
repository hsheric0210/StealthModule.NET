using System;

namespace StealthModule
{
    public class ModuleException : Exception
    {
        public ModuleException() { }
        public ModuleException(string message) : base(message) { }
        public ModuleException(string message, Exception innerException) : base(message, innerException) { }
    }
}
