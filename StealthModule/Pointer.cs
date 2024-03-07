using System;
using System.Runtime.InteropServices;

namespace StealthModule
{
    /// <summary>
    /// A wrapper class for UIntPtr to provide additional pointer arithmetic, alignment and checks.
    /// </summary>
    public readonly struct Pointer
    {
        public static readonly Pointer Zero = new Pointer(UIntPtr.Zero);

        public static int Size => IntPtr.Size;

        public static bool Is64Bit => Size == 8;

        private readonly UIntPtr value;

        private Pointer(UIntPtr value) => this.value = value;

        // (Auto-)Boxing functions (object -> Pointer)

        public static implicit operator Pointer(IntPtr value) => new Pointer((UIntPtr)unchecked((ulong)value.ToInt64()));
        public static implicit operator Pointer(UIntPtr value) => new Pointer(value);
        public static implicit operator Pointer(long value) => new Pointer((UIntPtr)unchecked((ulong)value));
        public static implicit operator Pointer(ulong value) => new Pointer((UIntPtr)value);
        public static implicit operator Pointer(int value) => new Pointer((UIntPtr)unchecked((uint)value));
        public static implicit operator Pointer(uint value) => new Pointer((UIntPtr)value);

        // (Auto-)Unboxing functions (Pointer -> object)

        public static implicit operator IntPtr(Pointer value) => new IntPtr(unchecked((long)value.value));
        public static implicit operator UIntPtr(Pointer value) => value.value;
        public static explicit operator int(Pointer value) => unchecked((int)value.value.ToUInt32());
        public static explicit operator uint(Pointer value) => value.value.ToUInt32();
        public static explicit operator long(Pointer value) => unchecked((long)value.value.ToUInt64());
        public static explicit operator ulong(Pointer value) => value.value.ToUInt64();

        // Direct read/write

        public T Read<T>() => (T)Marshal.PtrToStructure(this, typeof(T));

        public Pointer ReadPointer() => (Pointer)Marshal.PtrToStructure(this, typeof(IntPtr));

        public void Write<T>(T buffer) => Marshal.StructureToPtr(buffer, this, false);

        // Pointer arithmetics

        public static Pointer operator +(Pointer value, Pointer offset) => Is64Bit ? (Pointer)((ulong)value + (ulong)offset) : (Pointer)((uint)value + (uint)offset);
        public static Pointer operator +(Pointer value, IntPtr offset) => Is64Bit ? (Pointer)((ulong)value + unchecked((ulong)offset.ToInt64())) : (Pointer)((uint)value + unchecked((uint)offset.ToInt32()));
        public static Pointer operator +(Pointer value, UIntPtr offset) => Is64Bit ? (Pointer)((ulong)value + offset.ToUInt64()) : (Pointer)((uint)value + offset.ToUInt32());
        public static Pointer operator +(Pointer value, int offset) => value + (uint)offset; // overflow may occur
        public static Pointer operator +(Pointer value, uint offset) => value + (ulong)offset;
        public static Pointer operator +(Pointer value, long offset) => value + (ulong)offset; // overflow may occur
        public static Pointer operator +(Pointer value, ulong offset) => (Pointer)((ulong)value + offset);

        public static Pointer operator -(Pointer value, Pointer offset) => Is64Bit ? (Pointer)((ulong)value - (ulong)offset) : (Pointer)((uint)value - (uint)offset);
        public static Pointer operator -(Pointer value, IntPtr offset) => Is64Bit ? (Pointer)((ulong)value - unchecked((ulong)offset.ToInt64())) : (Pointer)((uint)value - unchecked((uint)offset.ToInt32()));
        public static Pointer operator -(Pointer value, UIntPtr offset) => Is64Bit ? (Pointer)((ulong)value - offset.ToUInt64()) : (Pointer)((uint)value - offset.ToUInt32());
        public static Pointer operator -(Pointer value, int offset) => value - (uint)offset; // overflow may occur
        public static Pointer operator -(Pointer value, uint offset) => value - (ulong)offset;
        public static Pointer operator -(Pointer value, long offset) => value - (ulong)offset; // overflow may occur
        public static Pointer operator -(Pointer value, ulong offset) => (Pointer)((ulong)value - offset);

        // Align

        public static Pointer operator |(Pointer value, UIntPtr v) => Is64Bit ? (Pointer)((ulong)value | v.ToUInt64()) : (Pointer)((uint)value | v.ToUInt32());
        public Pointer AlignDown(UIntPtr align) => (Pointer)(value.ToUInt64() & ~(align.ToUInt64() - 1));
        public bool SpanBoundary(uint Size, int BoundaryBits) => value.ToUInt64() >> BoundaryBits < (value.ToUInt64() + Size) >> BoundaryBits;

        public bool IsInvalidHandle() => value == UIntPtr.Zero || value == (Is64Bit ? unchecked((UIntPtr)(ulong)-1L) : unchecked((UIntPtr)(uint)-1));

        // Comparison operator

        public static bool operator ==(Pointer value1, Pointer value2) => value1.value == value2.value;

        public static bool operator !=(Pointer value1, Pointer value2) => value1.value != value2.value;

        public override string ToString() => Is64Bit ? ((ulong)value).ToString("X16") : ((ulong)value).ToString("X8");

        public override bool Equals(object obj) => obj is Pointer other && value == other.value;

        public override int GetHashCode() => (int)this;
    }
}
