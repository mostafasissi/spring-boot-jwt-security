package com.example.firstappspringsecurity.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.aspectj.weaver.patterns.IToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService ;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final String authorisationHeader = request.getHeader("Authorization");
        final String jwt ;
        final String userEmail ;
        if(authorisationHeader == null || !authorisationHeader.startsWith("Bearer ")){// the token header start with "Bearer " [Authorization: Bearer <token_value> ]
            filterChain.doFilter(request , response); // passe to others filter
            return;
        }
        jwt = authorisationHeader.substring(7); // length of "Bearer " is 7
        userEmail = jwtService.extractUserEmail(jwt);
        if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null){ // if the user is not authenticated
            // get user from the database
            UserDetails userDetails = userDetailsService.loadUserByUsername(userEmail);
            if (jwtService.isTokenValidat(jwt,userDetails)){ // cheek if the user if valid or not
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails ,
                        null ,
                        userDetails.getAuthorities()
                );
                authenticationToken.setDetails(
                        new WebAuthenticationDetails(request)
                );
                // update the security contexte holder
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        }

        // passe to next filter

        filterChain.doFilter(request , response);
    }
}
