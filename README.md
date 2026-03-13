# Rxss-Scan

Rxss-Scan 是一款轻量级的 Burp Suite 插件，用于自动化检测流量中的反射型 XSS 漏洞。

Rxss-Scan会自动将Proxy中响应Content-Type为text/html的GET请求参数的值替换为00N"<>abc，并检测响应中是否包含该字符串
