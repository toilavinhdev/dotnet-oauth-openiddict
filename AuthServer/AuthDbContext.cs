using Microsoft.EntityFrameworkCore;

namespace AuthServer;

public sealed class AuthDbContext(DbContextOptions<AuthDbContext> options) : DbContext(options)
{

}