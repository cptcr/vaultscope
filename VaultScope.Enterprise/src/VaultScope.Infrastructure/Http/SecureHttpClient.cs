using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;

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
            CookieContainer = new CookieContainer()
        };
        
        // Configure SSL/TLS validation for localhost
        if (options.AllowInsecureLocalhost)
        {
            _handler.ServerCertificateCustomValidationCallback = (sender, cert, chain, errors) =>
            {
                // Allow self-signed certificates for localhost only
                if (sender is HttpRequestMessage request)
                {
                    var host = request.RequestUri?.Host;
                    if (IsLocalhost(host))
                    {
                        _logger.LogDebug("Allowing self-signed certificate for localhost: {Host}", host);
                        return true;
                    }
                }
                
                return errors == System.Net.Security.SslPolicyErrors.None;
            };
        }
        
        _httpClient = new HttpClient(_handler)
        {
            Timeout = TimeSpan.FromMilliseconds(options.TimeoutMs)
        };
        
        // Set default headers
        _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd(options.UserAgent);
        _httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("*/*"));
        
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
            _logger.LogDebug("Sending {Method} request to {Uri}", request.Method, request.RequestUri);
            
            var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            
            _logger.LogDebug("Received {StatusCode} response from {Uri}", 
                response.StatusCode, request.RequestUri);
            
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
    }
    
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
}