namespace NetPasswordHash;

public class PasswordHashOptions
{
    public string Algorithm { get; set; }
    public int SaltLength { get; set; }
    public int Iterations { get; set; }
}
