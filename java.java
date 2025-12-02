package com.proxy;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Enumeration;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet("/proxy")
public class ProxyServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    
    // 安全设置：限制访问的域名（可选）
    private static final String[] ALLOWED_DOMAINS = {
        "example.com", 
        "wikipedia.org",
        "news.ycombinator.com"
    };
    
    // 安全设置：禁止访问的域名
    private static final String[] BLOCKED_DOMAINS = {
        "localhost",
        "127.0.0.1",
        "192.168.",
        "10.",
        "172.16.",
        "internal.",
        "admin."
    };
    
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        
        String targetUrl = request.getParameter("url");
        
        if (targetUrl == null || targetUrl.trim().isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "URL parameter is required");
            return;
        }
        
        // 安全检查
        if (!isUrlAllowed(targetUrl)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access to this URL is not allowed");
            return;
        }
        
        try {
            // 创建目标URL连接
            URL url = new URL(targetUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            
            // 设置请求方法
            conn.setRequestMethod("GET");
            
            // 设置超时时间
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);
            
            // 复制请求头（可选，可以限制只复制特定头部）
            Enumeration<String> headerNames = request.getHeaderNames();
            while (headerNames.hasMoreElements()) {
                String headerName = headerNames.nextElement();
                // 跳过某些敏感头部
                if (!headerName.equalsIgnoreCase("host") && 
                    !headerName.equalsIgnoreCase("connection") &&
                    !headerName.equalsIgnoreCase("content-length")) {
                    conn.setRequestProperty(headerName, request.getHeader(headerName));
                }
            }
            
            // 设置User-Agent（避免被目标服务器拒绝）
            conn.setRequestProperty("User-Agent", 
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
            
            // 获取响应
            int responseCode = conn.getResponseCode();
            
            // 设置响应状态码
            response.setStatus(responseCode);
            
            // 复制响应头
            for (String headerKey : conn.getHeaderFields().keySet()) {
                if (headerKey != null && 
                    !headerKey.equalsIgnoreCase("transfer-encoding") &&
                    !headerKey.equalsIgnoreCase("content-encoding")) {
                    response.setHeader(headerKey, conn.getHeaderField(headerKey));
                }
            }
            
            // 设置CORS头部（允许前端访问）
            response.setHeader("Access-Control-Allow-Origin", "*");
            
            // 复制响应内容
            InputStream inputStream;
            if (responseCode >= 400) {
                inputStream = conn.getErrorStream();
            } else {
                inputStream = conn.getInputStream();
            }
            
            OutputStream outputStream = response.getOutputStream();
            byte[] buffer = new byte[4096];
            int bytesRead;
            
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
            
            inputStream.close();
            outputStream.flush();
            conn.disconnect();
            
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, 
                "Proxy error: " + e.getMessage());
        }
    }
    
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        // 对于POST请求，类似处理但需要处理请求体
        response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED, 
            "POST method not yet implemented");
    }
    
    // 安全检查方法
    private boolean isUrlAllowed(String urlString) {
        try {
            URL url = new URL(urlString);
            String host = url.getHost().toLowerCase();
            
            // 检查是否在黑名单中
            for (String blocked : BLOCKED_DOMAINS) {
                if (host.contains(blocked.toLowerCase())) {
                    return false;
                }
            }
            
            // 如果ALLOWED_DOMAINS为空，则允许所有（不推荐）
            if (ALLOWED_DOMAINS.length == 0) {
                return true;
            }
            
            // 检查是否在白名单中
            for (String allowed : ALLOWED_DOMAINS) {
                if (host.endsWith("." + allowed) || host.equals(allowed)) {
                    return true;
                }
            }
            
            return false;
        } catch (Exception e) {
            return false;
        }
    }
}