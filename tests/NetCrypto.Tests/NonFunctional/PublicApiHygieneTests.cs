using System.Reflection;
using FluentAssertions;

namespace NetCrypto.Tests.NonFunctional;

/// <summary>
/// NFR-1 — public API hygiene (backend isolation). Reflects over the exported surface of the
/// NetCrypto assembly and asserts that no parameter type, return type, property type, field
/// type, base type, or implemented interface originates from a forbidden backend assembly
/// (simple name starting with NSec, NBitcoin, or Nethermind) or from the
/// <c>NetCrypto.Native</c> namespace.
/// The sweep is a blocklist over <c>GetExportedTypes()</c>, so the PRD-sanctioned exceptions
/// (Microsoft.IdentityModel.Tokens.JsonWebKey, NetCid types, System/BCL types,
/// Microsoft.Extensions.DependencyInjection.Abstractions types) pass automatically, and any
/// public type added to the assembly later is covered without touching this test.
/// </summary>
public class PublicApiHygieneTests
{
    private static readonly string[] ForbiddenAssemblyPrefixes = ["NSec", "NBitcoin", "Nethermind"];

    private const string ForbiddenNamespace = "NetCrypto.Native";

    private const BindingFlags DeclaredPublic =
        BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;

    [Fact]
    public void ExportedSurface_ContainsNoBackendOrNativeTypes()
    {
        var assembly = typeof(KeyType).Assembly;
        var exportedTypes = assembly.GetExportedTypes();
        exportedTypes.Should().NotBeEmpty("the NetCrypto assembly must expose a public surface to scan");

        var violations = new List<string>();

        foreach (var type in exportedTypes)
        {
            // The exported type itself must not live in NetCrypto.Native.
            CheckType(type, $"{type.FullName} (exported type)", violations);

            if (type.BaseType is not null)
                CheckType(type.BaseType, $"{type.FullName} base type", violations);

            foreach (var implementedInterface in type.GetInterfaces())
                CheckType(implementedInterface, $"{type.FullName} implemented interface", violations);

            foreach (var constructor in type.GetConstructors(DeclaredPublic))
                foreach (var parameter in constructor.GetParameters())
                    CheckType(parameter.ParameterType, $"{type.FullName}..ctor parameter '{parameter.Name}'", violations);

            foreach (var method in type.GetMethods(DeclaredPublic))
            {
                CheckType(method.ReturnType, $"{type.FullName}.{method.Name} return type", violations);
                foreach (var parameter in method.GetParameters())
                    CheckType(parameter.ParameterType, $"{type.FullName}.{method.Name} parameter '{parameter.Name}'", violations);
            }

            foreach (var property in type.GetProperties(DeclaredPublic))
            {
                CheckType(property.PropertyType, $"{type.FullName}.{property.Name} property type", violations);
                foreach (var parameter in property.GetIndexParameters())
                    CheckType(parameter.ParameterType, $"{type.FullName}.{property.Name} index parameter '{parameter.Name}'", violations);
            }

            foreach (var field in type.GetFields(DeclaredPublic))
                CheckType(field.FieldType, $"{type.FullName}.{field.Name} field type", violations);

            foreach (var declaredEvent in type.GetEvents(DeclaredPublic))
                if (declaredEvent.EventHandlerType is not null)
                    CheckType(declaredEvent.EventHandlerType, $"{type.FullName}.{declaredEvent.Name} event handler type", violations);
        }

        violations.Should().BeEmpty(
            "no public signature may expose a backend type (NSec/NBitcoin/Nethermind) or a NetCrypto.Native type (NFR-1)");
    }

    [Fact]
    public void BackendAssemblies_AreActuallyReferenced_SoTheBlocklistIsMeaningful()
    {
        // Canary: if the backend packages were ever renamed, the prefix blocklist above would
        // silently stop matching anything. This fails first, prompting the prefixes to be updated.
        var referencedNames = typeof(KeyType).Assembly
            .GetReferencedAssemblies()
            .Select(name => name.Name ?? string.Empty)
            .ToArray();

        foreach (var prefix in ForbiddenAssemblyPrefixes)
        {
            referencedNames.Should().Contain(
                name => name.StartsWith(prefix, StringComparison.Ordinal),
                $"the blocklist prefix '{prefix}' should match a referenced backend assembly");
        }
    }

    [Fact]
    public void Detector_FlagsBackendTypes_PositiveControl()
    {
        // Positive control: prove the recursive detector actually fires on backend types,
        // including when nested inside arrays and generic instantiations. Without this, a
        // reflection bug could let the main sweep pass vacuously.
        var violations = new List<string>();

        CheckType(typeof(Nethermind.Crypto.Bls.BlsException), "control: direct", violations);
        CheckType(typeof(NSec.Cryptography.Key[]), "control: array element", violations);
        CheckType(typeof(Task<NBitcoin.Secp256k1.ECPrivKey>), "control: generic argument", violations);

        violations.Should().HaveCount(3);

        // Sanctioned types must NOT be flagged.
        CheckType(typeof(Microsoft.IdentityModel.Tokens.JsonWebKey), "control: sanctioned", violations);
        CheckType(typeof(NetCid.Cid), "control: sanctioned", violations);
        CheckType(typeof(byte[]), "control: sanctioned", violations);

        violations.Should().HaveCount(3, "sanctioned JWK/NetCid/BCL types are not backend types");
    }

    /// <summary>
    /// Recursively unwraps arrays, by-ref and pointer types, and generic instantiations, and
    /// records a violation for every constituent type that originates from a forbidden backend
    /// assembly or the NetCrypto.Native namespace.
    /// </summary>
    private static void CheckType(Type type, string location, List<string> violations)
    {
        if (type.IsGenericParameter)
            return; // a type variable (e.g. T) has no concrete origin of its own

        if (type.HasElementType)
        {
            // T[], T&, T* — inspect the element type.
            CheckType(type.GetElementType()!, location, violations);
            return;
        }

        if (IsForbidden(type))
        {
            violations.Add(
                $"{location} exposes forbidden type '{type.FullName}' from assembly '{type.Assembly.GetName().Name}'");
        }

        if (type.IsGenericType)
        {
            foreach (var argument in type.GetGenericArguments())
                CheckType(argument, location, violations);
        }
    }

    private static bool IsForbidden(Type type)
    {
        var assemblyName = type.Assembly.GetName().Name ?? string.Empty;
        if (ForbiddenAssemblyPrefixes.Any(prefix => assemblyName.StartsWith(prefix, StringComparison.Ordinal)))
            return true;

        var typeNamespace = type.Namespace ?? string.Empty;
        return typeNamespace == ForbiddenNamespace
            || typeNamespace.StartsWith(ForbiddenNamespace + ".", StringComparison.Ordinal);
    }
}
