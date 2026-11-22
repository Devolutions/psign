using System.Runtime.InteropServices;
using System.Text;

namespace Devolutions.Psign.Tests.Signing;

/// <summary>
/// Differential-testing bridge to the Rust <c>psign-portable-ffi</c> shared library (<c>psign_core.dll</c> /
/// <c>libpsign_core.so</c> / <c>libpsign_core.dylib</c>). Test-only interop: the library under test is pure C#. Set
/// <c>PSIGN_RUST_FFI</c> to the library path or build <c>cargo build -p psign-portable-ffi</c> at the repo root; tests skip
/// when it is unavailable.
/// </summary>
internal static class RustPortableFfi
{
    [StructLayout(LayoutKind.Sequential)]
    private struct FfiBuffer
    {
        public IntPtr Ptr;
        public UIntPtr Len;
        public UIntPtr Cap;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FfiResult
    {
        public uint StatusCode;
        public FfiBuffer Json;
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate FfiResult VersionFn();

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate FfiResult JsonFn(IntPtr requestJson, UIntPtr requestJsonLen);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void FreeFn(FfiBuffer buffer);

    private static readonly Lazy<IntPtr?> Library = new(() =>
    {
        var candidates = new List<string>();
        if (Environment.GetEnvironmentVariable("PSIGN_RUST_FFI") is { Length: > 0 } env)
        {
            candidates.Add(env);
        }

        var name = OperatingSystem.IsWindows() ? "psign_core.dll" : OperatingSystem.IsMacOS() ? "libpsign_core.dylib" : "libpsign_core.so";
        foreach (var profile in new[] { "debug", "release" })
        {
            candidates.Add(Path.Combine(Fixtures.RepoRoot, "target", profile, name));
        }

        foreach (var candidate in candidates)
        {
            if (File.Exists(candidate) && NativeLibrary.TryLoad(candidate, out var handle))
            {
                return handle;
            }
        }

        return null;
    });

    public static bool Available => Library.Value is not null;

    /// <summary>Skip the current test when the Rust FFI library is unavailable.</summary>
    public static void Require() =>
        Xunit.Skip.If(!Available, "Rust psign-portable-ffi not built (set PSIGN_RUST_FFI or run cargo build -p psign-portable-ffi)");

    /// <summary>Call <c>psign_core_{operation}</c> with <paramref name="requestJson"/> (ignored for <c>version</c>).</summary>
    public static (uint StatusCode, string Json) Invoke(string operation, string? requestJson)
    {
        Require();
        var lib = Library.Value!.Value;
        var free = Marshal.GetDelegateForFunctionPointer<FreeFn>(NativeLibrary.GetExport(lib, "psign_core_free"));
        FfiResult result;
        if (operation == "version")
        {
            result = Marshal.GetDelegateForFunctionPointer<VersionFn>(NativeLibrary.GetExport(lib, "psign_core_version"))();
        }
        else
        {
            var fn = Marshal.GetDelegateForFunctionPointer<JsonFn>(NativeLibrary.GetExport(lib, "psign_core_" + operation));
            if (requestJson is null)
            {
                result = fn(IntPtr.Zero, UIntPtr.Zero);
            }
            else
            {
                var bytes = Encoding.UTF8.GetBytes(requestJson);
                var handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
                try
                {
                    result = fn(handle.AddrOfPinnedObject(), (UIntPtr)bytes.Length);
                }
                finally
                {
                    handle.Free();
                }
            }
        }

        try
        {
            var json = new byte[(int)result.Json.Len];
            Marshal.Copy(result.Json.Ptr, json, 0, json.Length);
            return (result.StatusCode, Encoding.UTF8.GetString(json));
        }
        finally
        {
            free(result.Json);
        }
    }
}
