// Program.cs
var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls("http://0.0.0.0:8080");

var app = builder.Build();

app.Use(async (context, next) =>
{
    context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Append("X-Frame-Options", "DENY");
    context.Response.Headers.Append("Referrer-Policy", "no-referrer");
    context.Response.Headers.Append("Content-Security-Policy", "default-src 'self'");
    await next();
});

app.MapGet("/", () => Results.Content("""
    <!DOCTYPE html>
    <html lang="en">
    <head><meta charset="UTF-8"><title>CRA Pipeline Test App</title></head>
    <body>
        <h1>CRA Pipeline Test App (.NET)</h1>
        <p>Application is running correctly.</p>
        <p>Health endpoint: <a href="/health">/health</a></p>
        <p>API endpoint: <a href="/api/status">/api/status</a></p>
    </body>
    </html>
    """, "text/html"));

app.MapGet("/health", () => Results.Ok("OK"));

app.MapGet("/api/status", () => Results.Json(new { 
    status = "ok", 
    application = "cra-pipeline-test-dotnet" 
}));

app.Run();