namespace NetPasswordHash;

public interface IPasswordHash
{
    string Generate(string password, PasswordHashOptions options = null);
    bool Verify(string password, string hashedPassword);
    bool IsHashed(string password);
}

