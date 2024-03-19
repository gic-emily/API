package med.voll.api.infra.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import med.voll.api.domain.usuario.UsuarioRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import med.voll.api.infra.security.TokenService;
import java.io.IOException;

@Component
public class SecurityFilter extends OncePerRequestFilter {

    @Autowired
    private TokenService tokenService;

    @Autowired
    private UsuarioRepository repository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain){
    var tokenJWT = recuperarToken(request);

    if (tokenJWT != null){
        var subject = tokenService.getSubject(tokenJWT);
        var usuario = repository.findByLogin(subject);

        var authentication = new UsernamePasswordAuthenticationToken(usuario, null, usuario.getAuthorities());
       SecurityContextHolder.getContext().setAuthentication(authentication);
        System.out.println("LOGADO");
    }
        try {
            filterChain.doFilter(request, response);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (ServletException e) {
            throw new RuntimeException(e);
        }
    }
    private String recuperarToken(HttpServletRequest request) {
        var authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String token = authorizationHeader.substring(7).trim(); // Remover o prefixo "Bearer "
            // Remover as aspas duplas do token
            token = token.replaceAll("^\"|\"$", "");
            System.out.println("Token JWT recebido: " + token);
            return token;
        }
        return null;
    }



}

