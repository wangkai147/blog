package com.minzheng.blog.config;

import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author wangkai
 * @date 2022/08/17
 * <p>
 * JwtToken解析并生成authentication身份信息过滤器
 */
@SuppressWarnings("unchecked")
@Slf4j
@Component
public class JwtAuthorizationTokenFilter extends OncePerRequestFilter {

    @Value("${jwt.token-header-key}")
    private String tokenHeaderKey; //token请求头Key
    @Value("${jwt.token-prefix}")
    private String tokenPrefix; //token前缀
    @Value("${jwt.token-secret}")
    private String tokenSecret; //token秘钥

    /**
     * 解析token并生成authentication身份信息
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        // 获取请求头传递过来的token数据
        String token = request.getHeader(tokenHeaderKey);
        log.info("JwtAuthorizationTokenFilterLog >> token:{}", token);
        if (null == token || !token.startsWith(tokenPrefix + ":")) {
            //校验token，直接下一步过滤器，此时上线文中无用户信息，所有在后续认证环节失败
            chain.doFilter(request, response);
            return;
        }
//        boolean expiration = JwtTokenUtils.isExpiration( token );
//        if(expiration) {
//            // 过期了，拦截访问
//            chain.doFilter(request, response);
//            return;
//        }
        Claims claims;
        try {
            claims = Jwts.parser().setSigningKey(tokenSecret).parseClaimsJws(token.replace(tokenPrefix + ":", "")).getBody();
        } catch (Exception e) {
            chain.doFilter(request, response);
            return;
        }
        String username = claims.getSubject();
        List<String> roles = claims.get("role", List.class);
        List<SimpleGrantedAuthority> authorities = roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
        if (null != username) {
            // 生成authentication身份信息
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(username, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        chain.doFilter(request, response);
    }
}