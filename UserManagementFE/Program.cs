using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using Microsoft.Extensions.Logging;
using UserManagementFE;
using UserManagementFE.Services;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

// Cấu hình HttpClient với địa chỉ cơ sở của backend
builder.Services.AddScoped(sp => new HttpClient { BaseAddress = new Uri("http://localhost:5293/") });

// Đăng ký các dịch vụ
builder.Services.AddScoped<AuthService>();
builder.Services.AddScoped<UserService>();
builder.Services.AddScoped<RSAKeyService>();

// Đăng ký PublicKeyStore như một singleton service
builder.Services.AddScoped<IPublicKeyStore, PublicKeyStore>();

// Cấu hình logging
builder.Logging.SetMinimumLevel(LogLevel.Debug); // Đặt mức log tối thiểu là Debug
builder.Logging.AddConfiguration(builder.Configuration.GetSection("Logging"));
// Không cần AddConsole() vì Blazor WebAssembly tự động dùng WebAssemblyConsoleLogger

var host = builder.Build();

// Ví dụ về logging trong chương trình chính
var logger = host.Services.GetRequiredService<ILogger<Program>>();
logger.LogInformation("Application started.");

await host.RunAsync();
