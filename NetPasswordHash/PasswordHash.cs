using System.Security.Cryptography;
using System.Text;

namespace NetPasswordHash;

public class PasswordHash : IPasswordHash
{
    private static string saltChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    private static int saltCharsCount = saltChars.Length;

    public string Generate(string password, PasswordHashOptions? options = null)
    {
        if(string.IsNullOrEmpty(password)) throw new Exception("Password invalid");
        options  = options == null ? new PasswordHashOptions() : options;
        options.Algorithm = string.IsNullOrEmpty(options.Algorithm) ? "sha1" : options.Algorithm;
        options.SaltLength = options.SaltLength <= 0 ? 8 : options.SaltLength;
        options.Iterations = options.Iterations <= 0 ? 1 : options.Iterations; 
        var salt = GenerateSalt(options.SaltLength);
        return GenerateHash(options.Algorithm, salt, password, options.Iterations);
    }

    public bool IsHashed(string password)
    {
        if (string.IsNullOrEmpty(password)) return false;
        return password.Split('$').Length == 4;
    }

    public bool Verify(string password, string hashedPassword)
    {
        if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(hashedPassword)) return false;
        hashedPassword = MakeBackwardCompatible(hashedPassword);
        var parts = hashedPassword.Split('$');
        if (parts.Length != 4) return false;
        try {
            return GenerateHash(parts[0], parts[1], password, int.Parse(parts[2])) == hashedPassword;
        } catch (Exception e) {}
        return false;
    }

    private string GenerateSalt(int len) {
        if (len <=0 ) throw new Exception("Invalid salt length");
        var salt = "";
        var randomByte = RandomNumberGenerator.GetBytes((int)Math.Ceiling((decimal)len/(decimal)2));
        if (randomByte!=null) {
            return ByteToHexString(randomByte).Substring(0,len);
        } else {
            for (var i = 0; i < len; i++) {
                Random r = new Random();
                int rInt = r.Next(0, saltCharsCount); //for ints
                salt += saltChars[rInt];
            }
            return salt;
        }
    }

    private string GenerateHash(string algorithm, string salt, string password, int iterations = 1) {
        iterations = iterations <= 0 ? 1: iterations;
        try {
            var hashed = password;
            var saltBytes = Encoding.Default.GetBytes(salt);
            var hasher = GetHasher("sha1", saltBytes);
            for(var i=0; i<iterations; ++i) {
                var plainBytes = Encoding.Default.GetBytes(hashed);
                var hashedBytes = hasher.ComputeHash(plainBytes);
                hashed = ByteToHexString(hashedBytes);
            }
            return algorithm + '$' + salt + '$' + iterations + '$' + hashed;
        } catch (Exception e) {
            throw e;
        }
    }

    private string MakeBackwardCompatible(string hashedPassword) {
        var parts = hashedPassword.Split('$');
        if(parts.Length == 3) {
            var new_parts = new string[4];
            new_parts[0] = parts[0];
            new_parts[1] = parts[1];
            new_parts[2] = "1";
            new_parts[3] = parts[2];
            hashedPassword = String.Join("$", new_parts);
        }
        
        return hashedPassword;
    }
    private string ByteToHexString(byte[] data) {
        StringBuilder hex = new StringBuilder(data.Length * 2);
        foreach (byte b in data)
            hex.AppendFormat("{0:x2}", b);
        return hex.ToString();
    }

    private HashAlgorithm GetHasher(string algorithm, byte[] saltBytes) {
        HashAlgorithm hash;
        switch (algorithm.ToLower())
        {
            case "md5": 
                hash = new HMACMD5(saltBytes);
                break;
            case "sha256":
                hash = new HMACSHA256(saltBytes);
                break;
            case "sha384":
                hash = new HMACSHA384(saltBytes);
                break;
            case "sha512":
                hash = new HMACSHA512(saltBytes);
                break;
            default:
                hash = new HMACSHA1(saltBytes);
                break;
        }
        return hash;
    }
}
