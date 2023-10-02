package io.security.basicsecurity.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                .authorizeRequests()
                .anyRequest().authenticated(); // 인가 정책

        http
                .formLogin()
//                .loginPage("/loginPage") // API 지정 (해당 경로는 인증 과정을 pass해야함 -> 누구나 접근 가능하도록)
                .defaultSuccessUrl("/") // 인증 성공 후 root로 Redirect
                .failureUrl("/login") // 인증 실패 후 다시 login page로 Redirect
                .usernameParameter("userId") // 아이디 파라미터 이름을 userId로 지정
                .passwordParameter("passwd") // 패스워드 파라미터 이름을 passwd로 지정
                .loginProcessingUrl("/login_proc") // 로그인 프로세스 url 지정
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

                        System.out.println("authentication: " + authentication.getName());
                        response.sendRedirect("/");
                    }
                }) // 로그인 성공 시 호출할 handler 지정
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {

                        System.out.println("exception: " + exception.getMessage());
                        response.sendRedirect("/login");
                    }
                }) // 로그인 실패 시 호출할 handler 지정
                .permitAll(); // 해당 page url은 누구나 접근 가능함

        http
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login") // 단순 URL 지정
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {

                        HttpSession session = request.getSession(); // 현재 세션 확인
                        session.invalidate(); // 세션 무효화
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

                        // todo 추가 작업
                        response.sendRedirect("/login"); // .logoutSuccessUrl("/login")이 하는 역할과 동일
                    }
                }) // 로그아웃 성공 시 다양한 로직 수행
                .deleteCookies("remember-me") // 서버에서 삭제하고 싶은 쿠키명 작성
                .and()
                .rememberMe()
                .rememberMeParameter("remember")
                .tokenValiditySeconds(3600)
                .userDetailsService(userDetailsService);
    }
}
