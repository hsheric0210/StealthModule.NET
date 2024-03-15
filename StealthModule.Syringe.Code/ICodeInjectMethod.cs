using System.Diagnostics;

namespace StealthModule.Syringe.Code
{
    internal interface ICodeInjectMethod
    {
        bool Inject(Process remoteProcess, byte[] shellCode);
    }
}
