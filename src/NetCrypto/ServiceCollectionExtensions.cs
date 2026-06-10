using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace NetCrypto;

/// <summary>
/// Extension methods for registering NetCrypto services in <see cref="IServiceCollection"/>.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Add the default NetCrypto providers to the dependency injection container:
    /// <see cref="ICryptoProvider"/> → <see cref="DefaultCryptoProvider"/>,
    /// <see cref="IBbsCryptoProvider"/> → <see cref="DefaultBbsCryptoProvider"/>, and
    /// <see cref="IKeyGenerator"/> → <see cref="DefaultKeyGenerator"/>, each as a singleton.
    /// </summary>
    /// <remarks>
    /// <para>
    /// All registrations use <c>TryAddSingleton</c>, which is the Posture-1 swap seam:
    /// a consumer registration for any of these interfaces made <b>before</b> calling
    /// <see cref="AddNetCrypto"/> wins, replacing the default implementation without
    /// any change to NetCrypto itself (e.g. a FIPS-validated or HSM-backed
    /// <see cref="ICryptoProvider"/>).
    /// </para>
    /// <para>
    /// <see cref="IKeyStore"/> is intentionally <b>not</b> registered: NetCrypto ships no
    /// default key store implementation. Consumers register their own store, and signers
    /// are obtained from <see cref="KeyPair"/>s (<see cref="KeyPairSigner"/>) or from a
    /// store via <see cref="IKeyStore.CreateSignerAsync"/>.
    /// </para>
    /// </remarks>
    /// <param name="services">The service collection to add the registrations to.</param>
    /// <returns>The same <paramref name="services"/> instance, for chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> is <c>null</c>.</exception>
    public static IServiceCollection AddNetCrypto(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton<ICryptoProvider, DefaultCryptoProvider>();
        services.TryAddSingleton<IBbsCryptoProvider, DefaultBbsCryptoProvider>();
        services.TryAddSingleton<IKeyGenerator, DefaultKeyGenerator>();

        return services;
    }
}
