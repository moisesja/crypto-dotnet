// FR-17 mechanical coverage check: reflects over the NetCrypto public API surface and
// verifies that every public type name and every public declared method/property name
// appears in at least one samples/**/*.cs file. CI fails (exit 1) on uncovered members.
using System.Reflection;
using System.Runtime.CompilerServices;

// FR-17: the exemption list MUST stay empty, or each entry must carry a
// written '// justification:' reviewed by the maintainer.
string[] exemptions =
[
];

// args[0]: path to the samples directory (default: 'samples' relative to the cwd).
string samplesDir = args.Length > 0 ? args[0] : "samples";
if (!Directory.Exists(samplesDir))
{
    Console.Error.WriteLine($"ERROR: samples directory not found: {Path.GetFullPath(samplesDir)}");
    return 2;
}

// Concatenate every sample source file; coverage is a simple substring check, which is
// deliberately loose — the goal is "the name shows up in the learning path", not parsing.
string samplesText = string.Concat(
    Directory.EnumerateFiles(samplesDir, "*.cs", SearchOption.AllDirectories)
        .OrderBy(p => p, StringComparer.Ordinal)
        .Select(File.ReadAllText));

// Member names inherited from System.Object / System.Enum / System.Delegate (and the
// serialization plumbing on System.Exception) never need a dedicated sample, even when
// a NetCrypto type overrides them.
string[] inheritedNames =
[
    "ToString", "Equals", "GetHashCode", "GetType", "ReferenceEquals", "MemberwiseClone",
    "CompareTo", "HasFlag", "GetTypeCode",                  // System.Enum
    "Invoke", "BeginInvoke", "EndInvoke", "DynamicInvoke",  // System.Delegate
    "GetObjectData", "GetBaseException",                    // System.Exception
];

var uncovered = new List<string>();

foreach (Type type in typeof(NetCrypto.KeyType).Assembly.GetExportedTypes()
             .OrderBy(t => t.FullName, StringComparer.Ordinal))
{
    // Generic types reflect as e.g. "Foo`1"; the source-visible name is "Foo".
    string typeName = type.Name.Split('`')[0];
    Require(typeName, typeName);

    if (type.IsEnum || typeof(Delegate).IsAssignableFrom(type))
        continue; // enum values and delegate Invoke signatures: only the TYPE name needs coverage.

    const BindingFlags declaredPublic =
        BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;

    foreach (MethodInfo method in type.GetMethods(declaredPublic))
    {
        // IsSpecialName drops property/event accessors and operators; constructors are not
        // in GetMethods; DeclaredOnly drops everything inherited from System.* base classes.
        if (method.IsSpecialName) continue;
        if (method.IsDefined(typeof(CompilerGeneratedAttribute), inherit: false)) continue;
        if (inheritedNames.Contains(method.Name)) continue;
        Require($"{typeName}.{method.Name}", method.Name);
    }

    foreach (PropertyInfo property in type.GetProperties(declaredPublic))
    {
        if (property.IsDefined(typeof(CompilerGeneratedAttribute), inherit: false)) continue;
        Require($"{typeName}.{property.Name}", property.Name);
    }
}

if (uncovered.Count == 0)
{
    Console.WriteLine($"API coverage OK: every public NetCrypto type/method/property name appears in {samplesDir}/**/*.cs.");
    return 0;
}

foreach (string entry in uncovered)
    Console.WriteLine($"UNCOVERED: {entry}");
Console.Error.WriteLine($"FAILED: {uncovered.Count} public API name(s) missing from {samplesDir}/**/*.cs (FR-17).");
return 1;

void Require(string label, string name)
{
    if (exemptions.Contains(label)) return;
    if (!samplesText.Contains(name, StringComparison.Ordinal))
        uncovered.Add(label);
}
