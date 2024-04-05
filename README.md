## 중요
한번에 모든 코드를 이해하려고 하면 오히려 복잡해지면서 헷갈리게 된다.

## 코드 작성 flow
1. 회원가입을 위해 User, CustomUserDetails를 작성
2. 로그인시 Jwt가 필요하므로 JwtService(issueAccessToken) 작성
3. 로그인 api 작성 후 jwt 응답
4. test api 하나 만들어서 jwt 유효성 검사 진행하기 위해 jwtAuthenticationFilter 작성
5. SecurityConfig에 filter 등록
