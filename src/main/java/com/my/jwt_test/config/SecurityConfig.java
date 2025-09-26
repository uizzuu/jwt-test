package com.my.jwt_test.config;

import com.my.jwt_test.mjwt.JWTFilter;
import com.my.jwt_test.mjwt.JWTUtil;
import com.my.jwt_test.mjwt.LoginFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    /** AuthenticationManager가 인자로 받을
     * AuthenticationConfiguration 객체 생성자 주입 */
    private final AuthenticationConfiguration authenticationConfiguration;
    private final JWTUtil jwtUtil;
    public SecurityConfig(AuthenticationConfiguration authenticationConfiguration, JWTUtil jwtUtil) {

        this.authenticationConfiguration = authenticationConfiguration;
        this.jwtUtil = jwtUtil;
    }

    /** AuthenticationManager Bean 등록 */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {

        return configuration.getAuthenticationManager();
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        /** csrf -> disable */
        http
                .csrf((auth) -> auth.disable());
        /** form 로그인 방식 disable
         * 기존의 Security가 제공하는 로그인 양식이 아닌
         * 우리가 사용하는 로그인 폼을 사용하도록 하게 하는 것 */
        http
                .formLogin((auth) -> auth.disable());

        /** 경로별 인가작업 */
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/login", "/", "/join").permitAll()
                        /**"/login" Controller를 만들지 않아도 Security 에서 잡음*/
                           .requestMatchers("/admin").hasRole("ADMIN")
                        .anyRequest().authenticated());

        //LoginFilter 앞에 JWTFilter 등록
        http
                .addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class);


        /** 필터 추가 LoginFilter()는 인자를 받음
         * (AuthenticationManager() 메소드에 authenticationConfiguration 객체를 넣어야 함)
         * 따라서 등록 필요 */
        http
                .addFilterAt(new LoginFilter(
                        authenticationManager(authenticationConfiguration), jwtUtil
                ), UsernamePasswordAuthenticationFilter.class);

        /** 세션 설정
         * 로그인하면 세션을 끊음 */
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }
}
