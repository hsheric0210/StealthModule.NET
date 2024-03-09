using System.Runtime.InteropServices;
using System;
using System.IO;

namespace StealthModule
{
    public class FileModule : IModule
    {
        public ExportResolver Exports { get; }

        public Pointer BaseAddress { get; }

        public FileModule(string dllFilePath)
        {
            // Check file exists
            if (!File.Exists(dllFilePath))
            {
                throw new InvalidOperationException("Filepath not found.");
            }

            // Open file handle
            UNICODE_STRING ObjectName = new UNICODE_STRING();
            NativeMethods.RtlInitUnicodeString(ref ObjectName, @"\??\" + dllFilePath);
            var objectNameAddress = Marshal.AllocHGlobal(Marshal.SizeOf(ObjectName));
            Marshal.StructureToPtr(ObjectName, objectNameAddress, true);

            OBJECT_ATTRIBUTES objectAttributes = new OBJECT_ATTRIBUTES();
            objectAttributes.Length = Marshal.SizeOf(objectAttributes);
            objectAttributes.ObjectName = objectNameAddress;
            objectAttributes.Attributes = 0x40; // OBJ_CASE_INSENSITIVE

            var ioStatusBlock = new IO_STATUS_BLOCK();

            var fileHandle = IntPtr.Zero;
            var status = NativeMethods.NtOpenFile(
                ref fileHandle,
                FileAccessFlags.FILE_READ_DATA | FileAccessFlags.FILE_EXECUTE | FileAccessFlags.FILE_READ_ATTRIBUTES | FileAccessFlags.SYNCHRONIZE,
                ref objectAttributes,
                ref ioStatusBlock,
                FileShareFlags.FILE_SHARE_READ | FileShareFlags.FILE_SHARE_DELETE,
                FileOpenFlags.FILE_SYNCHRONOUS_IO_NONALERT | FileOpenFlags.FILE_NON_DIRECTORY_FILE);
            if (!NativeMethods.NT_SUCCESS(status))
                throw new ModuleException("Can't open the file: NtOpenFile returned " + status);

            // Create section from hFile
            var sectionHandle = IntPtr.Zero;
            ulong maxSize = 0;
            status = NativeMethods.NtCreateSection(
                ref sectionHandle,
                ACCESS_MASK.SECTION_ALL_ACCESS,
                IntPtr.Zero,
                ref maxSize,
                MemoryProtection.READONLY,
                SectionTypes.SEC_IMAGE,
                fileHandle);
            if (!NativeMethods.NT_SUCCESS(status))
                throw new ModuleException("Unable to create section: NtCreateSection returned " + status);

            // Map view of file
            var mapBaseAddress = IntPtr.Zero;
            status = NativeMethods.NtMapViewOfSection(
                sectionHandle,
                (IntPtr)(-1),
                ref mapBaseAddress,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                ref maxSize,
                0x2,
                0x0,
                MemoryProtection.READWRITE);
            if (!NativeMethods.NT_SUCCESS(status) && status != NTSTATUS.ImageNotAtBase)
                throw new ModuleException("Unable to map view of section: NtMapViewOfSection returned " + status);

            BaseAddress = mapBaseAddress;
            Exports = new ExportResolver(BaseAddress);
        }

        public void Dispose()
        {
            // todo
        }
    }
}
