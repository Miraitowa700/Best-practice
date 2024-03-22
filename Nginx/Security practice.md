#不在错误页面和服务器header中发送nginx版本号
server_tokens off;

#Content-Security-Policy 标头是 X-XSS-Protection 标头的改进版本，并提供额外的安全层。它是非常强大的标头，旨在防止 XSS 和数据注入攻击。CSP 指示浏览器加载允许在网站上加载的内容。目前所有主流浏览器都提供对内容安全策略的全部或部分支持。
add_header Content-Security-Policy "default-src 'self'; font-src *;img-src * data:; script-src *; style-src *" ;

#X-Frame-Options 标头用于通过禁用网站上的 iframe 来保护您的网站免受点击劫持攻击。目前所有主流网络浏览器都支持它。通过此标头，您可以告诉浏览器不要将您的网页嵌入到frame/iframe 中。
add_header X-Frame-Options "SAMEORIGIN";

#X-XSS也称为跨站脚本标头，用于防御跨站脚本攻击。XSS 过滤器在现代 Web 浏览器（例如 Chrome、IE 和 Safari）中默认启用。当页面检测到反射的跨站脚本 (XSS) 攻击时，此标头会阻止页面加载。
add_header X-XSS-Protection "1; mode=block";

#Referrer-Policy是一个安全头字段，标识请求当前的网页的地址。通过检查引荐来源网址，新网页可以看到请求源自何处。Referrer-Policy 可以配置为使浏览器不向目标站点通知任何 URL 信息。
add_Header always set Referrer-Policy "strict-origin"

#Permissions-Policy 是一个新标头，允许站点控制浏览器中可以使用哪些 API 或功能。
add_header Permissions-Policy "geolocation=(),midi=(),sync-xhr=(),microphone=(),camera=(),magnetometer=(),gyroscope=(),fullscreen=(self),payment=()";

#可以告诉浏览器它仅能从你明确允许的域名下载内容,修改应用代码, 通过禁用css和js的 'unsafe-inline' 'unsafe-eval' 指标提高安全性。
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://ssl.google-analytics.com https://assets.zendesk.com https://connect.facebook.net; img-src 'self' https://ssl.google-analytics.com https://s-static.ak.facebook.com https://assets.zendesk.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://assets.zendesk.com; font-src 'self' https://themes.googleusercontent.com; frame-src https://assets.zendesk.com https://www.facebook.com https://s-static.ak.facebook.com https://tautt.zendesk.com; object-src 'none'";

#将所有 http 流量重定向到 https
server {
  listen 80 default_server;
  listen [::]:80 default_server;
  server_name .*.com;
  return 301 https://$host$request_uri;
}

#证书路径
server {
  listen 443 ssl http2;
  listen [::]:443 ssl http2;
  server_name .*.com;
  ssl_certificate /etc/nginx/ssl/epay_com.crt;
  ssl_certificate_key /etc/nginx/ssl/epay_com.key;

#启用会话恢复以提高 https 性能
ssl_session_cache shared:SSL:50m;
ssl_session_timeout 1d;
ssl_session_tickets off;

#启用 session resumption 提高HTTPS性能
ssl_session_cache shared:SSL:50m;
ssl_session_timeout 1d;
ssl_session_tickets off;

  #DHE密码器的Diffie-Hellman参数, 推荐 4096 位
openssl dhparam -dsaparam -out /etc/nginx/ssl/dhparam.pem 4096
ssl_dhparam /etc/nginx/ssl/dhparam.pem;

  #启用服务器端保护, 防止 BEAST 攻击
ssl_prefer_server_ciphers on;

  #禁用 SSLv3 和不安全的算法TLS 1.0、1.1
ssl_protocols TLSv1.2 TLSv1.3;

  #选择强度和安全加密算法
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305';

 #启用 session resumption 提高HTTPS性能
ssl_session_cache shared:SSL:50m;
ssl_session_timeout 1d;
ssl_session_tickets off;
ssl_prefer_server_ciphers off;

  #启用 ocsp stapling (网站可以以隐私保护、可扩展的方式向访客传达证书吊销信息的机制)
resolver 8.8.8.8 8.8.4.4;
ssl_stapling on;
ssl_stapling_verify on;
ssl_trusted_certificate /etc/nginx/ssl/star_forgott_com.crt;

  #启用 HSTS(HTTP Strict Transport Security) 
add_header Strict-Transport-Security "max-age=31536000; includeSubdomains; preload";


#白名单配置
location /admin/ {
    allow 192.16.1.0/24;
    allow all;
}

#黑名单配置
location /admin/ {
    allow 192.16.1.0/24;
    deny all;
}
set $allow false;
if ($http_x_forwarded_for = "211.144.204.2") { set $allow true; }
if ($http_x_forwarded_for ~ "108.2.66.[89]") { set $allow true; }
if ($allow = false) { return 404; }

#限制请求方法
if ($request_method !~ ^(GET|POST)$ ) {
    return 405;
}

#拒绝User-Agent
if ($http_user_agent ~* LWP::Simple|BBBike|wget|curl) {
    return 444;
}

#阻止推荐垃圾邮件
##Deny certain Referers ###
     if ( $http_referer ~* (babes|forsale|girl|jewelry|love|nudit|organic|poker|porn|sex|teen) )
     {
         # return 404;
         return 403;
     }

#图片防盗链
location /images/ {
    valid_referers none blocked www.epay.com epay.com;
    if ($invalid_referer) {
    return 403;
    }
}

#可以给不符合referer规则的请求重定向到一个默认的图片，比如下边这样
location /images/ {
    valid_referers blocked www.epay.com epay.com
    if ($invalid_referer) {
    rewrite ^/images/.*.(gif|jpg|jpeg|png)$ /static/qrcode.jpg last;
    }
}

#控制并发连接数,通过ngx_http_limit_conn_module模块限制一个IP的并发连接数
http {
    limit_conn_zone $binary_remote_addr zone=ops:10m;

    server {
        listen 80;
        server_name opstrip.com;
           
        root /home/project/webapp;
        index index.html;
        location / {
            limit_conn ops 10;
        }
        access_log /var/log/nginx/nginx_access.log main;
    }
}

#连接权限控制
实际上nginx的最大连接数是worker_processes乘以worker_connections的总数。
也就是说，下面的这个配置，就是4X65535，一般来说，我们会强调worker_processes设置成和核数相等，worker_connections并没有要求。但是这个设置其实给了攻击者空间，攻击者是可以同时发起这么多个连接，把服务器搞宕机，应该更合理配置这两个参数。
user  www;
worker_processes  4;
error_log  /var/log/nginx/nginx_error.log  crit;
pid        /var/nginx/nginx.pid;
events {
    use epoll;
    worker_connections 65535;
}

#缓冲区溢出攻击
缓冲区溢出攻击是通过将数据写入缓冲区并超出缓冲区边界和重写内存片段来实现的，限制缓冲区大小可有效防止.
client_body_buffer_size 1K;
client_header_buffer_size 1k;
client_max_body_size 1k;
large_client_header_buffers 21k;

#限制跨域访问
//启动通信之前检查给定通道的选项，HTTPS 具有所谓的预检请求。preflight是一种独立的请求类型，请求方法为GET、POST，用于查询当前支持的功能以及服务器的跨域策略。//
vi /etc/nginx/conf.d/default.conf
location / {
  add_header 'Access-Control-Allow-Origin' '*';
  add_header 'Access-Control-Allow-Methods' 'GET, POST, HEAD, OPTIONS';
   if ($request_method = 'GET|POST') {
      add_header 'Access-Control-Allow-Credentials' 'true';
      add_header 'Access-Control-Allow-Headers' 'DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type';
      add_header 'Access-Control-Max-Age' 57542400;
      add_header 'Content-Type' 'text/plain charset=UTF-8';
      add_header 'Content-Length' 0;
      return 204;
   }
}
测试预检请求，只需添加 -X OPTIONS，如下所示：
curl -s -D - -H "Origin: http://example.com" -X OPTIONS https://api.example.com/my-endpoint -o /dev/null
在 Java 中，可以使用  接口实现 CORS 过滤器，该过滤器将必要的 CORS 标头添加到 Java Web 应用程序的 HTTP 响应中。下面是 Java 中一个简单的 CORS 过滤器实现示例：
在 Java 中，可以使用 javax.servlet.Filter 接口实现 CORS 过滤器，该过滤器将必要的 CORS 标头添加到 Java Web 应用程序的 HTTP 响应中。下面是 Java 中一个简单的 CORS 过滤器实现示例：

import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
public class CORSFilter implements Filter {
@Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        httpResponse.setHeader("Access-Control-Allow-Origin", "*");
        httpResponse.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS");
        httpResponse.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
        if (httpRequest.getMethod().equals("OPTIONS")) {
            httpResponse.setStatus(HttpServletResponse.SC_OK);
            return;
        }
        chain.doFilter(request, response);
    }
    // other methods of the Filter interface go here
}

#密码保护目录
首先创建密码文件并添加一个名为 vivk 的用户： 编辑 nginx.conf 并保护所需的目录，如下所示：
mkdir /usr/local/nginx/conf/.htpasswd/
htpasswd -c /usr/local/nginx/conf/.htpasswd/passwd vivk
