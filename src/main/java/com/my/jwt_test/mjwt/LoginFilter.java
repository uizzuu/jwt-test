package com.my.jwt_test.mjwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.my.jwt_test.dto.CustomUserDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;
@RequiredArgsConstructor
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    /** JWTUtil 주입 */
    private final JWTUtil jwtUtil;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {

        //클라이언트 요청에서 username, password 추출 -> username을 사용할 경우
        // String username = obtainUsername(request);
        // String password = obtainPassword(request);

        try {
            // 별도 이메일 같은 거 쓸 때 -> JSON 형식 요청에서 email, password 파싱
            ObjectMapper objectMapper = new ObjectMapper();
            LoginRequest loginRequest = objectMapper.readValue(
                    request.getInputStream(), LoginRequest.class);
            /** email을 읽을 수 있게 해줌 */

            String email = loginRequest.getEmail();
            String password = loginRequest.getPassword();

            System.out.println("======"  + email);

            /** 스프링 시큐리티에서 username과 password를 검증하기 위해서는 token에 담아야 함
             * email과 password를 넣어주면 Spring이 받아서 인증 작업을 해줌*/
            UsernamePasswordAuthenticationToken authToken = new
                    UsernamePasswordAuthenticationToken(email, password, null);


            //token에 담은 검증을 위한 AuthenticationManager로 전달
            return authenticationManager.authenticate(authToken);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /** 로그인 성공시 실행하는 메소드 (여기서 JWT 토큰을 발급하면 됨)
     * 토큰을 발행하면, 리액트로 감 */
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response, FilterChain chain, Authentication authentication) {
        System.out.println("Success");
        //UserDetails
        CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();

        String userEmail = customUserDetails.getEmail();

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();

        String role = auth.getAuthority();

        String token = jwtUtil.createJwt(userEmail, role, 60*60*24L);
        /**60초 x 60 x 10 = 10시간*/

        response.addHeader("Authorization", "Bearer " + token);
        /** React한테 보내기,
         * 토큰을 전달할때 "Bearer " 한칸 띄고 보내기(약속) */
    }

    //로그인 실패시 실행하는 메소드
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request,
                                              HttpServletResponse response, AuthenticationException failed) {
        System.out.println("Fail");
        //로그인 실패시 401 응답 코드 반환
        response.setStatus(401);
    }
}
