package com.minzheng.blog.handler;

import com.alibaba.fastjson.JSON;
import com.minzheng.blog.dao.UserAuthDao;
import com.minzheng.blog.dto.UserInfoDTO;
import com.minzheng.blog.entity.UserAuth;
import com.minzheng.blog.util.BeanCopyUtils;
import com.minzheng.blog.util.UserUtils;
import com.minzheng.blog.vo.Result;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.stream.Collectors;

import static com.minzheng.blog.constant.CommonConst.APPLICATION_JSON;


/**
 * 登录成功处理
 *
 * @author yezhiqiu
 * @date 2021/07/28
 */
@Slf4j
@Component
public class AuthenticationSuccessHandlerImpl implements AuthenticationSuccessHandler {
    @Autowired
    private UserAuthDao userAuthDao;

    @Value("${jwt.token-header-key}")
    private String tokenHeaderKey; //token响应头Key
    @Value("${jwt.token-prefix}")
    private String tokenPrefix; //token前缀
    @Value("${jwt.token-secret}")
    private String tokenSecret; //token秘钥
    @Value("${jwt.token-expiration}")
    private Long tokenExpiration; //token过期时间

    @Override
    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException {
        UserInfoDTO userLoginDTO = BeanCopyUtils.copyObject(UserUtils.getLoginUser(), UserInfoDTO.class);
        // 生成token并设置响应头
        Claims claims = Jwts.claims();
        claims.put("role", authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()));
        // 返回登录信息
        String token = Jwts.builder()
                .setClaims(claims)
                .setSubject(userLoginDTO.getUsername()) //设置用户名
                .setExpiration(new Date(System.currentTimeMillis() + tokenExpiration)) //设置token过期时间
                .signWith(SignatureAlgorithm.HS512, tokenSecret).compact(); //设置token签名算法及秘钥
        httpServletResponse.addHeader(tokenHeaderKey, tokenPrefix + ":" + token); //设置token响应头
        httpServletResponse.setCharacterEncoding("UTF-8");
        httpServletResponse.setContentType(APPLICATION_JSON);
        httpServletResponse.getWriter().write(JSON.toJSONString(Result.ok(userLoginDTO)));
        // 更新用户ip，最近登录时间
        updateUserInfo();
    }

    /**
     * 更新用户信息
     */
    @Async
    public void updateUserInfo() {
        UserAuth userAuth = UserAuth.builder()
                .id(UserUtils.getLoginUser().getId())
                .ipAddress(UserUtils.getLoginUser().getIpAddress())
                .ipSource(UserUtils.getLoginUser().getIpSource())
                .lastLoginTime(UserUtils.getLoginUser().getLastLoginTime())
                .build();
        userAuthDao.updateById(userAuth);
    }

}
