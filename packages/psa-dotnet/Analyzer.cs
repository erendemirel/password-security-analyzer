using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace Psa
{
    /// <summary>
    /// Advisory password strength analyzer (P/Invoke → psa-ffi).
    /// Does not authorize account creation.
    /// </summary>
    public static class PasswordSecurityAnalyzer
    {
        private const string LibName = "psa_ffi";

        static PasswordSecurityAnalyzer()
        {
            NativeLibrary.SetDllImportResolver(typeof(PasswordSecurityAnalyzer).Assembly, Resolve);
        }

        private static IntPtr Resolve(string libraryName, System.Reflection.Assembly assembly, DllImportSearchPath? searchPath)
        {
            if (libraryName != LibName)
                return IntPtr.Zero;

            var env = Environment.GetEnvironmentVariable("PSA_FFI_PATH");
            if (!string.IsNullOrEmpty(env) && File.Exists(env))
                return NativeLibrary.Load(env);

            var baseDir = AppContext.BaseDirectory;
            var rid = RuntimeInformation.RuntimeIdentifier;
            if (string.IsNullOrEmpty(rid))
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    rid = "win-x64";
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                    rid = RuntimeInformation.OSArchitecture == Architecture.Arm64 ? "osx-arm64" : "osx-x64";
                else
                    rid = RuntimeInformation.OSArchitecture == Architecture.Arm64 ? "linux-arm64" : "linux-x64";
            }

            string nativeName =
                RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "psa_ffi.dll"
                : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "libpsa_ffi.dylib"
                : "libpsa_ffi.so";

            var candidates = new[]
            {
                Path.Combine(baseDir, "runtimes", rid, "native", nativeName),
                Path.Combine(baseDir, nativeName),
                Path.Combine(baseDir, "psa_ffi.dll"),
                Path.Combine(baseDir, "libpsa_ffi.so"),
                Path.Combine(baseDir, "libpsa_ffi.dylib"),
                Path.Combine(baseDir, "runtimes", "win-x64", "native", "psa_ffi.dll"),
                Path.Combine(baseDir, "runtimes", "linux-x64", "native", "libpsa_ffi.so"),
                Path.Combine(baseDir, "runtimes", "osx-arm64", "native", "libpsa_ffi.dylib"),
                Path.Combine(baseDir, "runtimes", "osx-x64", "native", "libpsa_ffi.dylib"),
                Path.Combine(baseDir, "native", "psa_ffi.dll"),
                Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "lib", nativeName)),
                Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "runtimes", rid, "native", nativeName)),
                Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "..", "..", "..", "target", "release", nativeName)),
                Path.GetFullPath(Path.Combine(Directory.GetCurrentDirectory(), "lib", nativeName)),
                Path.GetFullPath(Path.Combine(Directory.GetCurrentDirectory(), "..", "..", "target", "release", nativeName)),
            };

            foreach (var path in candidates)
            {
                if (File.Exists(path))
                    return NativeLibrary.Load(path);
            }

            return NativeLibrary.Load(LibName);
        }

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr psa_analyze_offline(byte[] password, byte[]? optionsJson);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr psa_analyze(byte[] password, byte[]? optionsJson);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr psa_check_pwned(byte[] password, byte[]? optionsJson);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr psa_model_info();

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        private static extern void psa_string_free(IntPtr s);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr psa_last_error();

        private static byte[] Utf8Z(string s) => Encoding.UTF8.GetBytes(s + "\0");

        private static byte[]? OptionsBytes(IDictionary<string, object?>? options)
        {
            if (options == null) return null;
            return Utf8Z(JsonSerializer.Serialize(options));
        }

        private static string TakeJson(IntPtr ptr)
        {
            if (ptr == IntPtr.Zero)
            {
                var errPtr = psa_last_error();
                var err = errPtr == IntPtr.Zero ? "psa-ffi error" : Marshal.PtrToStringUTF8(errPtr) ?? "psa-ffi error";
                throw new InvalidOperationException(err);
            }
            try
            {
                return Marshal.PtrToStringUTF8(ptr)
                       ?? throw new InvalidOperationException("null JSON from psa-ffi");
            }
            finally
            {
                psa_string_free(ptr);
            }
        }

        private static Dictionary<string, JsonElement> Parse(string json) =>
            JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json)
            ?? new Dictionary<string, JsonElement>();

        public static Dictionary<string, JsonElement> AnalyzeOffline(
            string password,
            IDictionary<string, object?>? options = null) =>
            Parse(TakeJson(psa_analyze_offline(Utf8Z(password), OptionsBytes(options))));

        public static Dictionary<string, JsonElement> Analyze(
            string password,
            IDictionary<string, object?>? options = null) =>
            Parse(TakeJson(psa_analyze(Utf8Z(password), OptionsBytes(options))));

        public static Dictionary<string, JsonElement> CheckPwned(
            string password,
            IDictionary<string, object?>? options = null) =>
            Parse(TakeJson(psa_check_pwned(Utf8Z(password), OptionsBytes(options))));

        public static Dictionary<string, JsonElement> ModelInfo() =>
            Parse(TakeJson(psa_model_info()));
    }
}
