using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

return Run(args);

static int Run(string[] args)
{
    string executableName = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "psign-tool.exe" : "psign-tool";
    string nativeExecutablePath = Path.Combine(AppContext.BaseDirectory, executableName);

    if (!File.Exists(nativeExecutablePath))
    {
        PrintUnsupportedRidMessage();
        return 1;
    }

    if (!EnsureExecutableBit(nativeExecutablePath))
    {
        return 1;
    }

    var processStartInfo = new ProcessStartInfo(nativeExecutablePath)
    {
        UseShellExecute = false,
    };

    foreach (string argument in args)
    {
        processStartInfo.ArgumentList.Add(argument);
    }

    try
    {
        using Process? process = Process.Start(processStartInfo);
        if (process is null)
        {
            Console.Error.WriteLine("Unable to start native psign-tool executable.");
            return 1;
        }

        process.WaitForExit();
        return process.ExitCode;
    }
    catch (Win32Exception ex)
    {
        Console.Error.WriteLine($"Unable to start native psign-tool executable: {ex.Message}");
        return 1;
    }
    catch (InvalidOperationException ex)
    {
        Console.Error.WriteLine($"Unable to start native psign-tool executable: {ex.Message}");
        return 1;
    }
}

static void PrintUnsupportedRidMessage()
{
    Console.Error.WriteLine("No native psign-tool executable is available for this runtime identifier in this package.");
    Console.Error.WriteLine($"Detected runtime identifier: {RuntimeInformation.RuntimeIdentifier}");
    Console.Error.WriteLine("Supported runtime identifiers: win-x64, win-arm64, linux-x64, linux-arm64, osx-x64, osx-arm64.");
    Console.Error.WriteLine("Install the tool on a supported platform, or download platform-specific binaries from psign release assets.");
}

static bool EnsureExecutableBit(string nativeExecutablePath)
{
    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
    {
        return true;
    }

    try
    {
        UnixFileMode mode = File.GetUnixFileMode(nativeExecutablePath);
        UnixFileMode executeMode = UnixFileMode.UserExecute;

        if ((mode & UnixFileMode.GroupRead) != 0)
        {
            executeMode |= UnixFileMode.GroupExecute;
        }

        if ((mode & UnixFileMode.OtherRead) != 0)
        {
            executeMode |= UnixFileMode.OtherExecute;
        }

        if ((mode & executeMode) != executeMode)
        {
            File.SetUnixFileMode(nativeExecutablePath, mode | executeMode);
        }

        return true;
    }
    catch (PlatformNotSupportedException ex)
    {
        Console.Error.WriteLine($"Unable to set execute permission on native psign-tool executable: {ex.Message}");
        return false;
    }
    catch (IOException ex)
    {
        Console.Error.WriteLine($"Unable to set execute permission on native psign-tool executable: {ex.Message}");
        return false;
    }
    catch (UnauthorizedAccessException ex)
    {
        Console.Error.WriteLine($"Unable to set execute permission on native psign-tool executable: {ex.Message}");
        return false;
    }
}
