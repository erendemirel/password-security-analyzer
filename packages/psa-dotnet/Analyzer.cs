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
            var candidates = new[]
            {
                Path.Combine(baseDir, "psa_ffi.dll"),
                Path.Combine(baseDir, "libpsa_ffi.so"),
                Path.Combine(baseDir, "libpsa_ffi.dylib"),
                Path.Combine(baseDir, "runtimes", "win-x64", "native", "psa_ffi.dll"),
                Path.Combine(baseDir, "native", "psa_ffi.dll"),
                // Dev: packages/psa-dotnet/lib and repo target/release
                // Smoke/bin/Debug/net5.0 → packages/psa-dotnet/lib
                Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "lib", "psa_ffi.dll")),
                // Smoke/bin/Debug/net5.0 → repo target/release (6 levels up)
                Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "..", "..", "..", "target", "release", "psa_ffi.dll")),
                Path.GetFullPath(Path.Combine(Directory.GetCurrentDirectory(), "lib", "psa_ffi.dll")),
                Path.GetFullPath(Path.Combine(Directory.GetCurrentDirectory(), "..", "..", "target", "release", "psa_ffi.dll")),
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
