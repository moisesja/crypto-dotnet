using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using NetCrypto;
using NSubstitute;

namespace NetCrypto.Tests.DependencyInjection;

/// <summary>
/// FR-9 acceptance tests for <see cref="ServiceCollectionExtensions.AddNetCrypto"/>:
/// default singleton registrations via TryAdd (the Posture-1 swap seam) and the
/// deliberate absence of an <see cref="IKeyStore"/> registration.
/// </summary>
public class ServiceCollectionExtensionsTests
{
    // ----------------------------------------------------------------
    // FR-9 AC: AddNetCrypto() then resolve — all three interfaces
    // yield the defaults.
    // ----------------------------------------------------------------

    [Fact]
    public void AddNetCrypto_Resolved_ICryptoProviderIsDefaultCryptoProvider()
    {
        using var provider = new ServiceCollection()
            .AddNetCrypto()
            .BuildServiceProvider();

        provider.GetRequiredService<ICryptoProvider>()
            .Should().BeOfType<DefaultCryptoProvider>();
    }

    [Fact]
    public void AddNetCrypto_Resolved_IBbsCryptoProviderIsDefaultBbsCryptoProvider()
    {
        using var provider = new ServiceCollection()
            .AddNetCrypto()
            .BuildServiceProvider();

        provider.GetRequiredService<IBbsCryptoProvider>()
            .Should().BeOfType<DefaultBbsCryptoProvider>();
    }

    [Fact]
    public void AddNetCrypto_Resolved_IKeyGeneratorIsDefaultKeyGenerator()
    {
        using var provider = new ServiceCollection()
            .AddNetCrypto()
            .BuildServiceProvider();

        provider.GetRequiredService<IKeyGenerator>()
            .Should().BeOfType<DefaultKeyGenerator>();
    }

    // ----------------------------------------------------------------
    // FR-9 AC: registrations are singletons — a second resolve returns
    // the same instance.
    // ----------------------------------------------------------------

    [Fact]
    public void AddNetCrypto_ResolvedTwice_ICryptoProviderIsSameInstance()
    {
        using var provider = new ServiceCollection()
            .AddNetCrypto()
            .BuildServiceProvider();

        var first = provider.GetRequiredService<ICryptoProvider>();
        var second = provider.GetRequiredService<ICryptoProvider>();

        second.Should().BeSameAs(first);
    }

    [Fact]
    public void AddNetCrypto_ResolvedTwice_IBbsCryptoProviderIsSameInstance()
    {
        using var provider = new ServiceCollection()
            .AddNetCrypto()
            .BuildServiceProvider();

        var first = provider.GetRequiredService<IBbsCryptoProvider>();
        var second = provider.GetRequiredService<IBbsCryptoProvider>();

        second.Should().BeSameAs(first);
    }

    [Fact]
    public void AddNetCrypto_ResolvedTwice_IKeyGeneratorIsSameInstance()
    {
        using var provider = new ServiceCollection()
            .AddNetCrypto()
            .BuildServiceProvider();

        var first = provider.GetRequiredService<IKeyGenerator>();
        var second = provider.GetRequiredService<IKeyGenerator>();

        second.Should().BeSameAs(first);
    }

    // ----------------------------------------------------------------
    // FR-9 AC: registering a fake ICryptoProvider BEFORE AddNetCrypto()
    // → the fake wins (TryAdd semantics; concept §5 Posture-1 swap seam).
    // ----------------------------------------------------------------

    [Fact]
    public void AddNetCrypto_FakeCryptoProviderRegisteredFirst_FakeWins()
    {
        var fake = Substitute.For<ICryptoProvider>();

        var services = new ServiceCollection();
        services.AddSingleton(fake);
        services.AddNetCrypto();

        using var provider = services.BuildServiceProvider();

        provider.GetRequiredService<ICryptoProvider>().Should().BeSameAs(fake);
    }

    [Fact]
    public void AddNetCrypto_FakeCryptoProviderRegisteredFirst_OtherDefaultsStillRegistered()
    {
        var fake = Substitute.For<ICryptoProvider>();

        var services = new ServiceCollection();
        services.AddSingleton(fake);
        services.AddNetCrypto();

        using var provider = services.BuildServiceProvider();

        provider.GetRequiredService<IBbsCryptoProvider>()
            .Should().BeOfType<DefaultBbsCryptoProvider>();
        provider.GetRequiredService<IKeyGenerator>()
            .Should().BeOfType<DefaultKeyGenerator>();
    }

    // ----------------------------------------------------------------
    // FR-9 AC: IKeyStore is NOT registered (no default store exists).
    // ----------------------------------------------------------------

    [Fact]
    public void AddNetCrypto_GetServiceIKeyStore_ReturnsNull()
    {
        using var provider = new ServiceCollection()
            .AddNetCrypto()
            .BuildServiceProvider();

        provider.GetService<IKeyStore>().Should().BeNull();
    }

    // ----------------------------------------------------------------
    // Argument validation and chaining contract.
    // ----------------------------------------------------------------

    [Fact]
    public void AddNetCrypto_NullServices_ThrowsArgumentNullException()
    {
        var act = () => ServiceCollectionExtensions.AddNetCrypto(null!);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void AddNetCrypto_Called_ReturnsSameServiceCollectionForChaining()
    {
        var services = new ServiceCollection();

        var result = services.AddNetCrypto();

        result.Should().BeSameAs(services);
    }
}
