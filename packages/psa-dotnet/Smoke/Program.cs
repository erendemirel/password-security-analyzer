using System;
using System.Linq;
using Psa;

static int Fail(string msg)
{
    Console.Error.WriteLine(msg);
    return 1;
}

var info = PasswordSecurityAnalyzer.ModelInfo();
if (!info["advisory"].GetBoolean())
    return Fail($"advisory={info["advisory"]}");

var weak = PasswordSecurityAnalyzer.AnalyzeOffline("password");
if (weak["label"].GetString() != "weak")
    return Fail($"password label={weak["label"]}");

var alpha = PasswordSecurityAnalyzer.AnalyzeOffline("abcdefghijklmnopqrstuvwxyz");
if (alpha["label"].GetString() != "weak")
    return Fail($"alphabet label={alpha["label"]}");
var reasons = alpha["reasons"].EnumerateArray().Select(e => e.GetString()).ToList();
if (!reasons.Contains("sequential_run"))
    return Fail($"reasons={string.Join(",", reasons)}");

Console.WriteLine("dotnet smoke OK");
return 0;
