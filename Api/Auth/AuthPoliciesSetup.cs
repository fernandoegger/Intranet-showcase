namespace Api.Auth;

public static class AuthPoliciesSetup
{
    public static IServiceCollection AddAuthorizationPolicies(this IServiceCollection services)
    {
        services.AddAuthorization(options =>
        {
            options.AddPolicy(AuthConstants.Policies.Admin, policy => 
                policy.RequireRole(AuthConstants.Roles.Admin));
        });

        return services;
    }
}