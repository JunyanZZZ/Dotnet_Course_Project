using System.Collections.Concurrent;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddOpenApi();
builder.Services.AddSingleton<ErrorHandlingMiddleware>();
builder.Services.AddSingleton<TokenAuthenticationMiddleware>();
builder.Services.AddSingleton<RequestResponseLoggingMiddleware>();

var app = builder.Build();

// Order matters: exception handling wraps the rest of the pipeline, authentication
// gates API access, and request/response logging surrounds endpoint execution.
app.UseMiddleware<ErrorHandlingMiddleware>();
app.UseMiddleware<TokenAuthenticationMiddleware>();
app.UseMiddleware<RequestResponseLoggingMiddleware>();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

var users = new ConcurrentDictionary<int, User>();
var nextId = 0;

// ConcurrentDictionary.Values provides a thread-safe snapshot. Avoid sorting the full
// collection on every request so listing users remains linear as the collection grows.
app.MapGet("/users", () => Results.Ok(users.Values));

app.MapGet("/users/{id:int}", (int id) =>
    users.TryGetValue(id, out var user) ? Results.Ok(user) : Results.NotFound());

app.MapPost("/users", (UserRequest request) =>
{
    var errors = Validate(request);
    if (errors.Count > 0)
    {
        return Results.ValidationProblem(errors);
    }

    var id = Interlocked.Increment(ref nextId);
    var user = new User(id, request.Name!.Trim(), request.Email!.Trim());
    users[id] = user;

    return Results.Created($"/users/{id}", user);
});

app.MapPut("/users/{id:int}", (int id, UserRequest request) =>
{
    var errors = Validate(request);
    if (errors.Count > 0)
    {
        return Results.ValidationProblem(errors);
    }

    var updatedUser = new User(id, request.Name!.Trim(), request.Email!.Trim());
    // TryUpdate avoids re-adding a user if it is deleted between the lookup and update.
    while (users.TryGetValue(id, out var existingUser))
    {
        if (users.TryUpdate(id, updatedUser, existingUser))
        {
            return Results.Ok(updatedUser);
        }
    }

    return Results.NotFound();
});

app.MapDelete("/users/{id:int}", (int id) =>
    users.TryRemove(id, out _) ? Results.NoContent() : Results.NotFound());

app.Run();

static Dictionary<string, string[]> Validate(UserRequest? request)
{
    var errors = new Dictionary<string, string[]>();

    if (request is null)
    {
        errors[string.Empty] = ["A user request body is required."];
        return errors;
    }

    if (string.IsNullOrWhiteSpace(request.Name))
    {
        errors[nameof(request.Name)] = ["Name is required."];
    }
    else if (request.Name.Trim().Length > 100)
    {
        errors[nameof(request.Name)] = ["Name must be 100 characters or fewer."];
    }

    if (string.IsNullOrWhiteSpace(request.Email))
    {
        errors[nameof(request.Email)] = ["Email is required."];
    }
    else if (request.Email.Trim().Length > 254 || !new EmailAddressAttribute().IsValid(request.Email.Trim()))
    {
        errors[nameof(request.Email)] = ["A valid email address is required."];
    }

    return errors;
}

record User(int Id, string Name, string Email);
record UserRequest(string? Name, string? Email);

sealed class ErrorHandlingMiddleware(RequestDelegate next, ILogger<ErrorHandlingMiddleware> logger)
{
    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await next(context);
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "Unhandled exception processing {Method} {Path}",
                context.Request.Method, context.Request.Path);

            if (context.Response.HasStarted)
            {
                throw;
            }

            context.Response.Clear();
            context.Response.StatusCode = StatusCodes.Status500InternalServerError;
            await context.Response.WriteAsJsonAsync(new { error = "Internal server error." });
        }
    }
}

sealed class TokenAuthenticationMiddleware(RequestDelegate next, IConfiguration configuration)
{
    public async Task InvokeAsync(HttpContext context)
    {
        var expectedToken = configuration["Authentication:Token"];
        var authorization = context.Request.Headers.Authorization.ToString();
        var suppliedToken = authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
            ? authorization[7..].Trim()
            : string.Empty;

        var valid = !string.IsNullOrWhiteSpace(expectedToken)
            && CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(suppliedToken),
                Encoding.UTF8.GetBytes(expectedToken));

        if (!valid)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsJsonAsync(new { error = "Unauthorized." });
            return;
        }

        await next(context);
    }
}

sealed class RequestResponseLoggingMiddleware(RequestDelegate next, ILogger<RequestResponseLoggingMiddleware> logger)
{
    public async Task InvokeAsync(HttpContext context)
    {
        logger.LogInformation("HTTP {Method} {Path} started", context.Request.Method, context.Request.Path);
        context.Response.OnStarting(() =>
        {
            logger.LogInformation("HTTP {Method} {Path} responded {StatusCode}",
                context.Request.Method, context.Request.Path, context.Response.StatusCode);
            return Task.CompletedTask;
        });

        await next(context);
    }
}
