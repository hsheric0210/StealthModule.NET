using System;
using System.Runtime.InteropServices;

namespace StealthModule
{
    /// <summary>
    /// A wrapper class for UIntPtr to provide additional pointer arithmetic, alignment and checks.
    /// </summary>
    public readonly struct Pointer
    {
        public static readonly Pointer Zero = new Pointer(IntPtr.Zero);

        public static int Size => IntPtr.Size;

        public static bool Is64Bit => Size == 8;

        private readonly IntPtr value;

        private Pointer(IntPtr value) => this.value = value;

        // (Auto-)Boxing functions (object -> Pointer)

        public static implicit operator Pointer(IntPtr value) => new Pointer(value);
        public static implicit operator Pointer(UIntPtr value) => new Pointer((IntPtr)unchecked((long)value.ToUInt64()));
        public static explicit operator Pointer(long value) => new Pointer((IntPtr)value);
        public static explicit operator Pointer(ulong value) => new Pointer((IntPtr)unchecked((long)value));
        public static explicit operator Pointer(int value) => new Pointer((IntPtr)value);
        public static explicit operator Pointer(uint value) => new Pointer((IntPtr)unchecked((int)value));

        // (Auto-)Unboxing functions (Pointer -> object)

        public static implicit operator IntPtr(Pointer value) => value.value;
        public static implicit operator UIntPtr(Pointer value) => new UIntPtr(unchecked((ulong)value.value.ToInt64()));
        public static explicit operator int(Pointer value) => value.value.ToInt32();
        public static explicit operator uint(Pointer value) => unchecked((uint)value.value.ToInt32());
        public static explicit operator long(Pointer value) => value.value.ToInt64();
        public static explicit operator ulong(Pointer value) => unchecked((ulong)value.value.ToInt64());

        // Direct read/write

        public T Read<T>() => (T)Marshal.PtrToStructure(this, typeof(T));

        public Pointer Read() => (Pointer)(IntPtr)Marshal.PtrToStructure(this, typeof(IntPtr));

        public void Write<T>(T buffer) => Marshal.StructureToPtr(buffer, this, false);
        public void Write(Pointer buffer) => Marshal.StructureToPtr((IntPtr)buffer, this, false);

        // Pointer arithmetics - Add

        public static Pointer operator +(Pointer value, Pointer offset)
            => value + offset.value;

        public static Pointer operator +(Pointer value, IntPtr offset)
            => Is64Bit
                ? (Pointer)(value.value.ToInt64() + offset.ToInt64())
                : (Pointer)(value.value.ToInt32() + offset.ToInt32());

        public static Pointer operator +(Pointer value, UIntPtr offset)
            => Is64Bit
                ? (Pointer)(value.value.ToInt64() + unchecked((long)offset.ToUInt64()))
                : (Pointer)(value.value.ToInt32() + unchecked((int)offset.ToUInt32()));

        public static Pointer operator +(Pointer value, int offset)
            => (Pointer)(value.value.ToInt64() + offset);

        public static Pointer operator +(Pointer value, uint offset)
            => Is64Bit
                ? (Pointer)(value.value.ToInt64() + offset)
                : (Pointer)(value.value.ToInt32() + unchecked((int)offset));

        // Pointer arithmetics - Subtract

        public static Pointer operator -(Pointer value, Pointer offset)
            => value - offset.value;

        public static Pointer operator -(Pointer value, IntPtr offset)
            => Is64Bit
                ? (Pointer)(value.value.ToInt64() - offset.ToInt64())
                : (Pointer)(value.value.ToInt32() - offset.ToInt32());

        public static Pointer operator -(Pointer value, UIntPtr offset)
            => Is64Bit
                ? (Pointer)(value.value.ToInt64() - unchecked((long)offset.ToUInt64()))
                : (Pointer)(value.value.ToInt32() - unchecked((int)offset.ToUInt32()));

        public static Pointer operator -(Pointer value, int offset)
            => (Pointer)(value.value.ToInt64() - offset);

        public static Pointer operator -(Pointer value, uint offset)
            => Is64Bit
                ? (Pointer)(value.value.ToInt64() - offset)
                : (Pointer)(value.value.ToInt32() - unchecked((int)offset));

        // Align

        public static Pointer operator |(Pointer value, UIntPtr v)
            => Is64Bit
                ? (Pointer)unchecked((long)(unchecked((ulong)value.value.ToInt64()) | v.ToUInt64()))
                : (Pointer)unchecked((int)(unchecked((uint)value.value.ToInt32()) | v.ToUInt32()));

        public Pointer AlignDown(UIntPtr align)
            => (Pointer)unchecked((long)(unchecked((ulong)value.ToInt64()) & ~(align.ToUInt64() - 1)));

        public bool SpanBoundary(uint Size, int BoundaryBits)
            => unchecked((ulong)value.ToInt64()) >> BoundaryBits < (unchecked((ulong)value.ToInt64()) + Size) >> BoundaryBits;

        public bool IsInvalidHandle() => value == IntPtr.Zero || value == (Is64Bit ? (IntPtr)(long)-1 : (IntPtr)(int)-1);

        // Comparison operator

        public static bool operator ==(Pointer value1, Pointer value2) => value1.value == value2.value;

        public static bool operator !=(Pointer value1, Pointer value2) => value1.value != value2.value;

        public override string ToString() => Is64Bit ? ((ulong)value).ToString("X16") : ((ulong)value).ToString("X8");

        public override bool Equals(object obj) => obj is Pointer other && value == other.value;

        public override int GetHashCode() => (int)this;

        // intptr to uint

        private uint ToUInt32(this IntPtr value) => unchecked((uint)value.ToInt32());
        private ulong ToUInt64(this IntPtr value) => unchecked((ulong)value.ToInt64());

        // uintptr to int

        private int ToInt32(this UIntPtr value) => unchecked((int)value.TouInt32());
        private long ToInt64(this UIntPtr value) => unchecked((long)value.TouInt64());

    }
}
