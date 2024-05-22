package com.nadhem.produits.security;

import java.util.Collections;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import jakarta.servlet.http.HttpServletRequest;



@Configuration
@EnableWebSecurity
public class SecurityConfig {
	
	
	@Autowired
	KeycloakRoleConverter keycloakRoleConverter;
	
	@Bean
	public SecurityFilterChain filterChain (HttpSecurity http) throws Exception
	{
		http.sessionManagement( session -> 
		session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
		.csrf( csrf -> csrf.disable()) 
		
		.cors(cors -> cors.configurationSource(new CorsConfigurationSource() {
            @Override
            public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                CorsConfiguration cors = new CorsConfiguration();
                cors.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
                cors.setAllowedMethods(Collections.singletonList("*"));
                cors.setAllowedHeaders(Collections.singletonList("*"));
                cors.setExposedHeaders(Collections.singletonList("Authorization"));

                return cors;
            }
        }))
				
	     .authorizeHttpRequests( requests -> requests
			    		  .requestMatchers("/api/all/**").hasAnyAuthority("ADMIN","USER")
						  .requestMatchers(HttpMethod.GET,"/api/getbyid/**").hasAnyAuthority("ADMIN",
						  "USER")
						  .requestMatchers(HttpMethod.POST,"/api/addprod/**").hasAnyAuthority("ADMIN")
						  .requestMatchers(HttpMethod.PUT,"/api/updateprod/**").hasAuthority("ADMIN")
						  .requestMatchers(HttpMethod.DELETE,"/api/delprod/**").hasAuthority("ADMIN")
						.anyRequest().authenticated() )
	     				  .oauth2ResourceServer(rs->rs.jwt(jwt->
	     				  			jwt.jwtAuthenticationConverter(keycloakRoleConverter)));
	    
	     
	 
		
	return http.build();
	}
	

}
//authentication ->policies => constraint pour le mot de passe
//real setting -> login -> user registration
//realm setting -> user registration -> assign role  (decoshi hide inherited roles ki te7eb temchi thabet)
//realm setting -> Email  ( bech configuri les emails )

//realm setting -> Verify email (compte yewali actif ken ma verifi email mete3ou)
//realm setting -> forgot password (bech resti passworf)
//ki login bil social auto registration

//~/go/bin/MailHog  ti start mailhog server
