using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Devolutions.Psign.PowerShell.Native;

internal static class PsignNativeResolver
{
    private const string LibraryName = "psign_portable";

    [ModuleInitializer]
    internal static void Register()
    {
        NativeLibrary.SetDllImportResolver(typeof(PsignNativeResolver).Assembly, Resolve);
    }

    private static IntPtr Resolve(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (!StringComparer.Ordinal.Equals(libraryName, LibraryName))
        {
            return IntPtr.Zero;
        }

        string moduleRoot = GetModuleRoot(assembly);
        string rid = GetCurrentRid();
        string fileName = GetNativeFileName();
        string nativePath = Path.Combine(moduleRoot, "runtimes", rid, "native", fileName);

        if (!File.Exists(nativePath))
        {
            throw new DllNotFoundException(
                $"Could not find psign portable native library for RID '{rid}'. Expected '{nativePath}'.");
        }

        return NativeLibrary.Load(nativePath, assembly, searchPath);
    }

    private static string GetModuleRoot(Assembly assembly)
    {
        string assemblyDirectory = Path.GetDirectoryName(assembly.Location)
            ?? throw new InvalidOperationException("The module assembly has no load path.");
        DirectoryInfo directory = new(assemblyDirectory);

        if (StringComparer.OrdinalIgnoreCase.Equals(directory.Name, "net8.0")
            && directory.Parent is { Name: "lib" } lib
            && lib.Parent is not null)
        {
            return lib.Parent.FullName;
        }

        return assemblyDirectory;
    }

    private static string GetNativeFileName()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return "psign_portable.dll";
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            return "libpsign_portable.dylib";
        }

        return "libpsign_portable.so";
    }

    private static string GetCurrentRid()
    {
        string os = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "win"
            : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "osx"
            : "linux";
        string arch = RuntimeInformation.ProcessArchitecture switch
        {
            Architecture.X64 => "x64",
            Architecture.Arm64 => "arm64",
            Architecture.X86 => "x86",
            Architecture.Arm => "arm",
            _ => RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant(),
        };

        return $"{os}-{arch}";
    }
}
