using System.Net.Http.Headers;
using System.Text;
using VaultScope.Core.Models;
using VaultScope.Infrastructure.Json;

namespace VaultScope.Infrastructure.Http;

public class HttpRequestBuilder
{
    private readonly HttpRequestMessage _request;
    private readonly Dictionary<string, string> _headers = new();
    private readonly Dictionary<string, string> _queryParams = new();
    
    private HttpRequestBuilder(HttpMethod method, string url)
    {
        _request = new HttpRequestMessage(method, url);
    }
    
    public static HttpRequestBuilder Create(HttpMethod method, string url)
    {
        return new HttpRequestBuilder(method, url);
    }
    
    public static HttpRequestBuilder Get(string url) => Create(HttpMethod.Get, url);
    public static HttpRequestBuilder Post(string url) => Create(HttpMethod.Post, url);
    public static HttpRequestBuilder Put(string url) => Create(HttpMethod.Put, url);
    public static HttpRequestBuilder Delete(string url) => Create(HttpMethod.Delete, url);
    public static HttpRequestBuilder Patch(string url) => Create(new HttpMethod("PATCH"), url);
    public static HttpRequestBuilder Head(string url) => Create(HttpMethod.Head, url);
    public static HttpRequestBuilder Options(string url) => Create(HttpMethod.Options, url);
    
    public HttpRequestBuilder WithHeader(string name, string value)
    {
        _headers[name] = value;
        return this;
    }
    
    public HttpRequestBuilder WithHeaders(Dictionary<string, string> headers)
    {
        foreach (var header in headers)
        {
            _headers[header.Key] = header.Value;
        }
        return this;
    }
    
    public HttpRequestBuilder WithAuthentication(AuthenticationResult? auth)
    {
        if (auth == null || !auth.IsAuthenticated)
            return this;
        
        switch (auth.Type)
        {
            case AuthenticationType.Bearer:
                if (!string.IsNullOrEmpty(auth.Token))
                {
                    _request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", auth.Token);
                }
                break;
                
            case AuthenticationType.Basic:
                if (auth.Headers.TryGetValue("Authorization", out var basicAuth))
                {
                    _request.Headers.TryAddWithoutValidation("Authorization", basicAuth);
                }
                break;
                
            case AuthenticationType.ApiKey:
                foreach (var header in auth.Headers)
                {
                    _headers[header.Key] = header.Value;
                }
                break;
                
            case AuthenticationType.Cookie:
                if (auth.Cookies.Any())
                {
                    var cookieHeader = string.Join("; ", auth.Cookies.Select(c => $"{c.Key}={c.Value}"));
                    _headers["Cookie"] = cookieHeader;
                }
                break;
                
            case AuthenticationType.OAuth2:
                if (!string.IsNullOrEmpty(auth.Token))
                {
                    _request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", auth.Token);
                }
                break;
                
            case AuthenticationType.Custom:
                foreach (var header in auth.Headers)
                {
                    _headers[header.Key] = header.Value;
                }
                break;
        }
        
        return this;
    }
    
    public HttpRequestBuilder WithQueryParam(string name, string value)
    {
        _queryParams[name] = value;
        return this;
    }
    
    public HttpRequestBuilder WithQueryParams(Dictionary<string, string> queryParams)
    {
        foreach (var param in queryParams)
        {
            _queryParams[param.Key] = param.Value;
        }
        return this;
    }
    
    public HttpRequestBuilder WithJsonContent(object content)
    {
        var json = System.Text.Json.JsonSerializer.Serialize(content, VaultScopeJsonContext.Default.Object);
        _request.Content = new StringContent(json, Encoding.UTF8, "application/json");
        return this;
    }
    
    public HttpRequestBuilder WithStringContent(string content, string mediaType = "text/plain")
    {
        _request.Content = new StringContent(content, Encoding.UTF8, mediaType);
        return this;
    }
    
    public HttpRequestBuilder WithFormUrlEncodedContent(Dictionary<string, string> formData)
    {
        _request.Content = new FormUrlEncodedContent(formData);
        return this;
    }
    
    public HttpRequestBuilder WithMultipartFormContent(MultipartFormDataContent content)
    {
        _request.Content = content;
        return this;
    }
    
    public HttpRequestBuilder WithTimeout(TimeSpan timeout)
    {
        // Note: Timeout is typically set on HttpClient, not on individual requests
        // This is here for API completeness
        return this;
    }
    
    public HttpRequestBuilder WithUserAgent(string userAgent)
    {
        _request.Headers.UserAgent.Clear();
        _request.Headers.UserAgent.ParseAdd(userAgent);
        return this;
    }
    
    public HttpRequestBuilder WithAccept(string mediaType)
    {
        _request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(mediaType));
        return this;
    }
    
    public HttpRequestBuilder WithReferer(string referer)
    {
        _request.Headers.Referrer = new Uri(referer);
        return this;
    }
    
    public HttpRequestMessage Build()
    {
        // Apply headers
        foreach (var header in _headers)
        {
            _request.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }
        
        // Apply query parameters
        if (_queryParams.Any())
        {
            var uriBuilder = new UriBuilder(_request.RequestUri!);
            var query = System.Web.HttpUtility.ParseQueryString(uriBuilder.Query);
            
            foreach (var param in _queryParams)
            {
                query[param.Key] = param.Value;
            }
            
            uriBuilder.Query = query.ToString();
            _request.RequestUri = uriBuilder.Uri;
        }
        
        return _request;
    }
    
    public static HttpRequestMessage BuildSecurityTestRequest(
        string url,
        HttpMethod method,
        string? payload = null,
        AuthenticationResult? auth = null,
        Dictionary<string, string>? customHeaders = null)
    {
        var builder = Create(method, url)
            .WithAuthentication(auth)
            .WithUserAgent("VaultScope/1.0 (Security Scanner)");
        
        if (!string.IsNullOrEmpty(payload))
        {
            builder.WithStringContent(payload, "application/json");
        }
        
        if (customHeaders != null)
        {
            builder.WithHeaders(customHeaders);
        }
        
        return builder.Build();
    }
}