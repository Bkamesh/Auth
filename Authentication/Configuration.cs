namespace Authentication
{

    public class JwtSettings
    {
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public string SecretKey { get; set; }
        public int TokenLifetime { get; set; }
    }
    public class LoginRequest
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }
    public class CookieSettings
    {
        public string ValidationType { get; set; }
        public int ExpirationTime { get; set; }
        public bool HttpOnly { get; set; }
        public bool Secure { get; set; }
    }

}
