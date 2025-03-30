using System.Text;
using DotnetApiCompleteAuth.Data;
using DotnetApiCompleteAuth.Models;
using DotnetApiCompleteAuth.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();

string connectionString = builder.Configuration.GetConnectionString("default");

builder.Services.AddDbContext<AppDbContext>(options => options.UseSqlServer(connectionString));

// for identity
builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<AppDbContext>()
                .AddDefaultTokenProviders();

// JWT Configuration
// Authentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.SaveToken = true;
    options.RequireHttpsMetadata = false;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidAudience = builder.Configuration["JWT:ValidAudience"],
        ValidIssuer = builder.Configuration["JWT:ValidIssuer"],
        ClockSkew = TimeSpan.Zero,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JWT:secret"]))
    };
});

builder.Services.AddTransient<ITokenService, TokenService>();

var app = builder.Build();

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

await DbSeeder.SeedDataAsync(app);

app.Run();
