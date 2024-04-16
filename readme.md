![img.png](img.png)  

Protects against CSRF attacks by default for unsafe HTTP methods,  so no additional code is necessary.
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
			// ...
			.csrf(Customizer.withDefaults());
		return http.build();
	}
}
```



## `CsrfTokenRepository`
- `HttpSessionCsrfTokenRepository` Stored in: `HttpSession` --> Used by Default
  - reads the token from:
    - HTTP request header named **X-CSRF-TOKEN**
    - or
    - HTTP request parameter named **_csrf**
- `CookieCsrfTokenRepository` Used for _support a JavaScript-based application_
  - writes to a cookie named **XSRF-TOKEN**
  - reads the token from:
    - HTTP request header named **X-XSRF-TOKEN**
    - or
    - HTTP request parameter named **_csrf**
- `YourCustomCsrfTokenRepository` --> You can Impl your own

## Integrating with CSRF Protection
1. include the CSRF token in HTTP Request
  - A form parameter
  - A request header
  - any other which is not automatically included by the browser

### HTML Forms
```html
<input type="hidden"
	name="_csrf"
	value="4bfd1575-3ad1-4d21-96c7-4ef2d9f86721"/>
```
Automatically included:
- ThymeLeaf
- Spring's tag library
- Any other view technology that integrates with `RequestDataValueProcessor` (via `CsrfRequestDataValueProcessor`)  

#### Important: TAke advantage of the `HttpServletResponse` 

`CsrfToken` is exposed in `HttpServletRequest` in the attribute named `_csrf`   

`JSP`
```jsp
<c:url var="logoutUrl" value="/logout"/>
<form action="${logoutUrl}"
	method="post">
<input type="submit"
	value="Log out" />
<input type="hidden"
	name="${_csrf.parameterName}"
	value="${_csrf.token}"/>
</form>
```

## JavaScript Applications
Typically use `JSON` instead of `HTML` then submit the `CSRF` 
within an HTTP request **header** instead of ~~a request **parameter**.~~  

- Did you know ?: Angular can automatically include the actual `CSRF` token as an HTTP request header.

### Single Page Applications
When storing the expected `CSRF` token in a **cookie** JS applications will only have
- access to the plain token value // `console.log(getCookie('XSRF-TOKEN'))`
- won't have access to the encoded value.  

Cookie storing the `CSRF` will be cleared upon:
- Authentication Success
- Logout Success
Spring Security defers loading a new CSRF token by default
- additionally work is required to return a fresh cookie.

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
			// ...
			.csrf((csrf) -> csrf
				.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
				.csrfTokenRequestHandler(new SpaCsrfTokenRequestHandler())
			)
			.addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class);
		return http.build();
	}
}

final class SpaCsrfTokenRequestHandler extends CsrfTokenRequestAttributeHandler {
	private final CsrfTokenRequestHandler delegate = new XorCsrfTokenRequestAttributeHandler();

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response, Supplier<CsrfToken> csrfToken) {
		/*
		 * Always use XorCsrfTokenRequestAttributeHandler to provide BREACH protection of
		 * the CsrfToken when it is rendered in the response body.
		 */
		this.delegate.handle(request, response, csrfToken);
	}

	@Override
	public String resolveCsrfTokenValue(HttpServletRequest request, CsrfToken csrfToken) {
		/*
		 * If the request contains a request header, use CsrfTokenRequestAttributeHandler
		 * to resolve the CsrfToken. This applies when a single-page application includes
		 * the header value automatically, which was obtained via a cookie containing the
		 * raw CsrfToken.
		 */
		if (StringUtils.hasText(request.getHeader(csrfToken.getHeaderName()))) {
			return super.resolveCsrfTokenValue(request, csrfToken);
		}
		/*
		 * In all other cases (e.g. if the request contains a request parameter), use
		 * XorCsrfTokenRequestAttributeHandler to resolve the CsrfToken. This applies
		 * when a server-side rendered form includes the _csrf request parameter as a
		 * hidden input.
		 */
		return this.delegate.resolveCsrfTokenValue(request, csrfToken);
	}
}

final class CsrfCookieFilter extends OncePerRequestFilter {

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		CsrfToken csrfToken = (CsrfToken) request.getAttribute("_csrf");
		// Render the token value to a cookie by causing the deferred token to be loaded
		csrfToken.getToken();

		filterChain.doFilter(request, response);
	}
}
```