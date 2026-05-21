using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Devolutions.Psign.PowerShell.Models;

namespace Devolutions.Psign.PowerShell.Native;

internal static unsafe class PsignNative
{
    private const string LibraryName = "psign_portable";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = null,
        WriteIndented = false,
    };

    internal static PortableSignature GetSignature(PortableGetSignatureRequest request)
    {
        return Invoke<PortableGetSignatureRequest, PortableSignature>(request, psign_portable_get_signature);
    }

    internal static PortableSignResponse Sign(PortableSignRequest request)
    {
        return Invoke<PortableSignRequest, PortableSignResponse>(request, psign_portable_sign);
    }

    private delegate PsignFfiResult NativeCall(IntPtr requestJsonPtr, UIntPtr requestJsonLen);

    private static TResponse Invoke<TRequest, TResponse>(TRequest request, NativeCall nativeCall)
    {
        byte[] requestJson = JsonSerializer.SerializeToUtf8Bytes(request, JsonOptions);
        PsignFfiResult result;
        fixed (byte* requestPtr = requestJson)
        {
            result = nativeCall((IntPtr)requestPtr, (UIntPtr)requestJson.Length);
        }

        byte[] responseJson;
        try
        {
            responseJson = CopyResponse(result.Json);
        }
        finally
        {
            psign_portable_free(result.Json);
        }

        if (result.StatusCode != 0)
        {
            PortableErrorResponse? error = JsonSerializer.Deserialize<PortableErrorResponse>(responseJson, JsonOptions);
            string message = error?.Message ?? Encoding.UTF8.GetString(responseJson);
            throw new PsignPortableException(result.StatusCode, message);
        }

        return JsonSerializer.Deserialize<TResponse>(responseJson, JsonOptions)
            ?? throw new PsignPortableException(result.StatusCode, "psign portable returned an empty JSON response.");
    }

    private static byte[] CopyResponse(PsignFfiBuffer buffer)
    {
        if (buffer.Ptr == IntPtr.Zero || buffer.Len == UIntPtr.Zero)
        {
            return [];
        }

        byte[] bytes = new byte[(int)buffer.Len];
        Marshal.Copy(buffer.Ptr, bytes, 0, bytes.Length);
        return bytes;
    }

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    private static extern PsignFfiResult psign_portable_get_signature(IntPtr requestJsonPtr, UIntPtr requestJsonLen);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    private static extern PsignFfiResult psign_portable_sign(IntPtr requestJsonPtr, UIntPtr requestJsonLen);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    private static extern void psign_portable_free(PsignFfiBuffer buffer);
}

[StructLayout(LayoutKind.Sequential)]
internal readonly struct PsignFfiBuffer
{
    public readonly IntPtr Ptr;
    public readonly UIntPtr Len;
    public readonly UIntPtr Cap;
}

[StructLayout(LayoutKind.Sequential)]
internal readonly struct PsignFfiResult
{
    public readonly uint StatusCode;
    public readonly PsignFfiBuffer Json;
}
