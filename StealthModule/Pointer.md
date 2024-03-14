# Pointer

Simple wrapper class for IntPtr and UIntPtr to add more pointer-related features such as Pointer Arithmetics.

Supports auto-boxing and auto-unboxing to IntPtr, UIntPtr. Also supports auto-boxing from other integer types, unboxing to other integer types.

All pointer arithmetics are handled in proper bits. In 64-bit, for example, all pointer arithmetics are handled in 64-bit integer space.

## IntPtr and UIntPtr to Pointer

```csharp
IntPtr intPtr = (IntPtr)0xbeef;
Pointer ptr = intPtr; // Implicit cast
```

```csharp
UIntPtr intPtr = (UIntPtr)0xdead;
Pointer ptr = intPtr; // Implicit cast
```

## Pointer arithmetics

```csharp
var a = (Pointer)0xbad;
var b = (Pointer)0xf00d;

var addPtr = a + b;
var subPtr = a - b;
var orPtr = a | b;
```
