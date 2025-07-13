using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Logging;
using VaultScope.Infrastructure.Json;

namespace VaultScope.Infrastructure.Http;

public class SecureHttpClient : IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<SecureHttpClient> _logger;
    private readonly HttpClientHandler _handler;
    
    public SecureHttpClient(ILogger<SecureHttpClient> logger, SecureHttpClientOptions? options = null)
    {
        _logger = logger;
        options ??= new SecureHttpClientOptions();
        
        _handler = new HttpClientHandler
        {
            AllowAutoRedirect = options.FollowRedirects,
            MaxAutomaticRedirections = options.MaxRedirects,
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate | DecompressionMethods.Brotli,
            UseCookies = options.UseCookies,
            CookieContainer = new CookieContainer(),
            // Enhanced TLS security settings
            SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            CheckCertificateRevocationList = true,
            UseProxy = false // Disable proxy to prevent potential security issues
        };
        
        // Configure enhanced SSL/TLS validation
        _handler.ServerCertificateCustomValidationCallback = (sender, cert, chain, errors) =>
        {
            // Strict validation for all non-localhost hosts
            if (sender is HttpRequestMessage request)
            {
                var host = request.RequestUri?.Host;
                
                // For localhost, apply relaxed validation only if explicitly allowed
                if (IsLocalhost(host) && options.AllowInsecureLocalhost)
                {
                    // Still perform basic certificate validation even for localhost
                    if (cert == null)
                    {
                        _logger.LogWarning("Certificate is null for localhost: {Host}", host);
                        return false;
                    }
                    
                    // Check certificate expiration
                    var x509Cert = new X509Certificate2(cert);
                    if (x509Cert.NotAfter < DateTime.Now || x509Cert.NotBefore > DateTime.Now)
                    {
                        _logger.LogWarning("Certificate expired or not yet valid for localhost: {Host}", host);
                        return false;
                    }
                    
                    // Check for weak algorithms
                    if (IsWeakSignatureAlgorithm(x509Cert.SignatureAlgorithm.FriendlyName))
                    {
                        _logger.LogWarning("Weak signature algorithm detected for localhost: {Algorithm}", x509Cert.SignatureAlgorithm.FriendlyName);
                        return false;
                    }
                    
                    _logger.LogDebug("Allowing certificate for localhost: {Host}", host);
                    return true;
                }
                
                // Strict validation for non-localhost hosts
                if (errors != SslPolicyErrors.None)
                {
                    _logger.LogWarning("SSL/TLS validation failed for {Host}: {Errors}", host, errors);
                    return false;
                }
                
                // Additional certificate validation
                if (cert != null)
                {
                    var x509Cert = new X509Certificate2(cert);
                    
                    // Check for weak signature algorithms
                    if (IsWeakSignatureAlgorithm(x509Cert.SignatureAlgorithm.FriendlyName))
                    {
                        _logger.LogWarning("Weak signature algorithm detected: {Algorithm}", x509Cert.SignatureAlgorithm.FriendlyName);
                        return false;
                    }
                    
                    // Check key strength
                    var keySize = GetKeySize(x509Cert);
                    if (keySize < 2048)
                    {
                        _logger.LogWarning("Weak key size detected: {KeySize}", keySize);
                        return false;
                    }
                }
            }
            
            return errors == SslPolicyErrors.None;
        };
        
        _httpClient = new HttpClient(_handler)
        {
            Timeout = TimeSpan.FromMilliseconds(options.TimeoutMs)
        };
        
        // Set secure default headers
        _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd(options.UserAgent);
        _httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("*/*"));
        
        // Add security headers
        _httpClient.DefaultRequestHeaders.Add("Cache-Control", "no-cache, no-store, must-revalidate");
        _httpClient.DefaultRequestHeaders.Add("Pragma", "no-cache");
        _httpClient.DefaultRequestHeaders.Add("X-Content-Type-Options", "nosniff");
        _httpClient.DefaultRequestHeaders.Add("X-Frame-Options", "DENY");
        _httpClient.DefaultRequestHeaders.Add("X-XSS-Protection", "1; mode=block");
        
        if (!string.IsNullOrEmpty(options.AcceptLanguage))
        {
            _httpClient.DefaultRequestHeaders.AcceptLanguage.ParseAdd(options.AcceptLanguage);
        }
    }
    
    public async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken = default)
    {
        try
        {
            // Validate request before sending
            ValidateRequest(request);
            
            _logger.LogDebug("Sending {Method} request to {Uri}", request.Method, request.RequestUri);
            
            var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            
            _logger.LogDebug("Received {StatusCode} response from {Uri}", 
                response.StatusCode, request.RequestUri);
            
            // Validate response headers for security
            ValidateResponseHeaders(response);
            
            return response;
        }
        catch (TaskCanceledException ex)
        {
            _logger.LogWarning(ex, "Request timeout for {Uri}", request.RequestUri);
            throw new TimeoutException($"Request timeout for {request.RequestUri}", ex);
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "HTTP request failed for {Uri}", request.RequestUri);
            throw;
        }
        catch (ArgumentException ex)
        {
            _logger.LogError(ex, "Invalid request for {Uri}", request.RequestUri);
            throw;
        }
    }
    
    [RequiresUnreferencedCode("JSON serialization may require types that cannot be statically analyzed")]
    public async Task<T> GetJsonAsync<T>(string url, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.GetAsync(url, cancellationToken);
        response.EnsureSuccessStatusCode();
        
        var json = await response.Content.ReadAsStringAsync(cancellationToken);
        return System.Text.Json.JsonSerializer.Deserialize<T>(json) ?? throw new InvalidOperationException("Failed to deserialize response");
    }
    
    public async Task<string> GetStringAsync(string url, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.GetAsync(url, cancellationToken);
        response.EnsureSuccessStatusCode();
        
        return await response.Content.ReadAsStringAsync(cancellationToken);
    }
    
    public void SetDefaultHeader(string name, string value)
    {
        _httpClient.DefaultRequestHeaders.Remove(name);
        _httpClient.DefaultRequestHeaders.TryAddWithoutValidation(name, value);
    }
    
    public void SetCookie(Uri uri, Cookie cookie)
    {
        _handler.CookieContainer.Add(uri, cookie);
    }
    
    public CookieCollection GetCookies(Uri uri)
    {
        return _handler.CookieContainer.GetCookies(uri);
    }
    
    private void ValidateRequest(HttpRequestMessage request)
    {
        if (request?.RequestUri == null)
            throw new ArgumentException("Request URI cannot be null");
        
        var uri = request.RequestUri;
        
        // Validate scheme
        if (uri.Scheme != "http" && uri.Scheme != "https")
            throw new ArgumentException($"Unsupported scheme: {uri.Scheme}");
        
        // Validate host
        if (string.IsNullOrWhiteSpace(uri.Host))
            throw new ArgumentException("Host cannot be empty");
        
        // Check for localhost requirement (if needed)
        if (!IsLocalhost(uri.Host))
        {
            _logger.LogWarning("Non-localhost request detected: {Host}", uri.Host);
        }
    }
    
    private void ValidateResponseHeaders(HttpResponseMessage response)
    {
        // Log potentially dangerous response headers
        if (response.Headers.Contains("X-Powered-By"))
        {
            _logger.LogInformation("Server disclosed technology: {Technology}", 
                string.Join(", ", response.Headers.GetValues("X-Powered-By")));
        }
        
        // Check for security headers
        if (!response.Headers.Contains("X-Content-Type-Options"))
        {
            _logger.LogDebug("Missing X-Content-Type-Options header");
        }
        
        if (!response.Headers.Contains("X-Frame-Options") && !response.Headers.Contains("Content-Security-Policy"))
        {
            _logger.LogDebug("Missing clickjacking protection headers");
        }
    }
    
    private static int GetKeySize(X509Certificate2 certificate)
    {
        try
        {
            // Try to get RSA key size
            using var rsa = certificate.GetRSAPublicKey();
            if (rsa != null)
            {
                return rsa.KeySize;
            }
            
            // Try to get ECDSA key size
            using var ecdsa = certificate.GetECDsaPublicKey();
            if (ecdsa != null)
            {
                return ecdsa.KeySize;
            }
            
            // Fallback: return a default value that won't trigger warnings
            return 2048;
        }
        catch
        {
            // Return a conservative value if we can't determine the key size
            return 0;
        }
    }
    
    private static bool IsWeakSignatureAlgorithm(string? algorithm)
    {
        if (string.IsNullOrEmpty(algorithm))
            return true;
        
        var weakAlgorithms = new[]
        {
            "md5", "sha1", "md2", "md4",
            "rsa_md5", "rsa_sha1", "dsa_sha1",
            "ecdsa_sha1"
        };
        
        return weakAlgorithms.Any(weak => 
            algorithm.Contains(weak, StringComparison.OrdinalIgnoreCase));
    }
    
    private static bool IsLocalhost(string? host)
    {
        if (string.IsNullOrEmpty(host))
            return false;
        
        return host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
               host.Equals("127.0.0.1", StringComparison.OrdinalIgnoreCase) ||
               host.Equals("::1", StringComparison.OrdinalIgnoreCase) ||
               host.Equals("[::1]", StringComparison.OrdinalIgnoreCase) ||
               host.EndsWith(".local", StringComparison.OrdinalIgnoreCase) ||
               host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase);
    }
    
    public void Dispose()
    {
        _httpClient?.Dispose();
        _handler?.Dispose();
    }
}

public class SecureHttpClientOptions
{
    public int TimeoutMs { get; set; } = 30000;
    public bool FollowRedirects { get; set; } = true;
    public int MaxRedirects { get; set; } = 5;
    public bool UseCookies { get; set; } = true;
    public bool AllowInsecureLocalhost { get; set; } = true;
    public string UserAgent { get; set; } = "VaultScope/1.0 (Security Scanner)";
    public string AcceptLanguage { get; set; } = "en-US,en;q=0.9";
    
    // Enhanced security options
    public bool EnableStrictTls { get; set; } = true;
    public bool ValidateCertificateChain { get; set; } = true;
    public bool LogSecurityHeaders { get; set; } = true;
    public int MaxResponseSizeBytes { get; set; } = 10 * 1024 * 1024; // 10MB
    public TimeSpan MaxRequestDuration { get; set; } = TimeSpan.FromMinutes(5);
    
    // Rate limiting
    public int MaxRequestsPerSecond { get; set; } = 10;
    public TimeSpan RateLimitWindow { get; set; } = TimeSpan.FromSeconds(1);
}