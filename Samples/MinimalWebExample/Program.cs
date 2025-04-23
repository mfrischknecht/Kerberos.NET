using Microsoft.Extensions.Options;
using Kerberos.NET;
using Kerberos.NET.Crypto;
using Microsoft.Extensions.Primitives;
using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);

builder.Logging.ClearProviders();
builder.Logging.AddConsole();

builder.Services.Configure<KerberosSettings>(
    builder.Configuration.GetSection("Kerberos"));

builder.Services.AddSingleton<IKerberosValidator>(services => {
    var settings = services.GetRequiredService<IOptions<KerberosSettings>>().Value;
    ArgumentNullException.ThrowIfNullOrEmpty(settings.Keytab);

    var keytabContents = File.ReadAllBytes(settings.Keytab);
    var keytab = new KeyTable(keytabContents);
    var validator = new KerberosValidator(keytab);
    return validator;
});

var app = builder.Build();

//Force initialization errors during startup instead of during the first request:
app.Services.GetRequiredService<IKerberosValidator>();

app.MapGet("/", async (
    HttpContext context,
    [FromServices] IKerberosValidator validator,
    [FromServices] ILogger<Program> logger
) => {

    if (context.Request.Headers.Authorization is not [string authHeader] || !authHeader.StartsWith("Negotiate "))
    {
        context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
        context.Response.Headers.Append("WWW-Authenticate", "Negotiate");
        await context.Response.WriteAsync("Unauthorized");
        return;
    }

    ClaimsPrincipal? user;
    try
    {
        var authenticator = new KerberosAuthenticator(validator);
        var identity = await authenticator.Authenticate(authHeader);
        user = new(identity);
    }
    catch (Exception ex)
    {
        logger.LogInformation(ex, "Client failed to authenticate via Kerberos");
        context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
        context.Response.Headers.Append("WWW-Authenticate", "Negotiate");
        await context.Response.WriteAsync("Unauthorized");
        return;
    }

    context.Response.StatusCode = (int)HttpStatusCode.OK;
    await context.Response.WriteAsync($"Welcome, {user.Identity?.Name ?? "Stranger"} !");
});

app.Run();


public sealed record KerberosSettings
{
    public string? Keytab { get; init; } = null;
}
