package com.minzheng.blog.config;

import com.minzheng.blog.handler.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.session.HttpSessionEventPublisher;


/**
 * Security配置类
 *
 * @author yezhiqiu
 * @date 2021/07/29
 */
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private AuthenticationEntryPointImpl authenticationEntryPoint;//自定义未登录处理器：返回状态码
    @Autowired
    private AuthenticationSuccessHandlerImpl authenticationSuccessHandler;//验证成功处理器(前后端分离)：生成token及响应状态码
    @Autowired
    private AuthenticationFailHandlerImpl authenticationFailHandler;//验证失败处理器(前后端分离)：返回状态码
    @Autowired
    private AccessDeniedHandlerImpl accessDeniedHandler;//自定义权限不足处理器：返回状态码
    @Autowired
    private LogoutSuccessHandlerImpl logoutSuccessHandler;//自定义注销成功处理器：返回状态码
    @Autowired
    private AccessDecisionManager accessDecisionManager; //自定义权限判断管理器
    @Autowired
    private FilterInvocationSecurityMetadataSource securityMetadataSource;//动态获取url权限配置
    @Autowired
    private JwtAuthorizationTokenFilter authorizationTokenFilter; //JwtToken解析并生成authentication身份信息过滤器
//    @Autowired
//    private SelfAuthenticationProvider selfAuthenticationProvider;
//    @Autowired
//    public void configureGlobal(AuthenticationManagerBuilder auth) {
//        auth.authenticationProvider(selfAuthenticationProvider);
//    }

    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

    /**
     * 密码加密
     *
     * @return {@link PasswordEncoder} 加密方式
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 配置权限
     *
     * @param http http
     * @throws Exception 异常
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // JwtToken解析并生成authentication身份信息过滤器
        http.addFilterBefore(authorizationTokenFilter, UsernamePasswordAuthenticationFilter.class);
        // 配置登录注销路径
        http.formLogin().loginProcessingUrl("/login")                        //自定义登录请求路径(post)
                .usernameParameter("username").passwordParameter("password") //自定义登录用户名密码属性名,默认为username和password
                .successHandler(authenticationSuccessHandler)                //登录成功
                .failureHandler(authenticationFailHandler)                   //登陆失败
                .and()
                .logout().logoutUrl("/logout")                               //自定义注销路径
                .logoutSuccessHandler(logoutSuccessHandler);                 //注销成功
        // 配置路由权限信息
        http.authorizeRequests()
                .withObjectPostProcessor(new ObjectPostProcessor<FilterSecurityInterceptor>() {
                    @Override
                    public <O extends FilterSecurityInterceptor> O postProcess(O fsi) {
                        fsi.setSecurityMetadataSource(securityMetadataSource);
                        fsi.setAccessDecisionManager(accessDecisionManager);
                        return fsi;
                    }
                }).anyRequest()
                .permitAll()//指定任何人都允许使用URL。
//                .authenticated()
                .and()
                .csrf().disable()// 去掉 CSRF（跨域）
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 使用 JWT，关闭session
                .and()
                .exceptionHandling()// 关闭跨站请求防护
                .authenticationEntryPoint(authenticationEntryPoint)                // 未登录处理
                .accessDeniedHandler(accessDeniedHandler);                          // 权限不足处理
//                .and()
//                .sessionManagement().maximumSessions(1).sessionRegistry(sessionRegistry());
    }

}
