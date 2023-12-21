package com.clonair.back.security.config;

import com.clonair.back.security.jwt.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Esta clase define las reglas de seguridad, filtros, y la gestión de sesiones.
 * */
@Configuration
@EnableWebSecurity // @EnableWebSecurity: Habilita la seguridad web en la aplicación.
@RequiredArgsConstructor // Genera automáticamente un constructor que incluya todos los campos marcados como final en una clase.
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter; // Es un filtro personalizado para procesar tokens JWT.
    private final AuthenticationProvider authProvider; // El proveedor de autenticación personalizado definido en ApplicationConfig.
    
    /**
     * Este método configura la seguridad en la aplicación
     * utilizando un patrón fluente (fluent API) proporcionado por Spring Security.
     * */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception { // http: Es el objeto HttpSecurity que se configura para establecer las reglas de seguridad.
        return http
                .csrf(csrf -> // Deshabilitar CSRF(Cross-Site Request Forgery) cuando se trabaja con una API REST.
                        csrf  // Ya que las aplicaciones RESTful no mantienen el estado de sesión por diseño, y CSRF se enfoca en la protección de sesiones.
                                .disable())
                .authorizeHttpRequests(authRequest ->
                        authRequest
                                .requestMatchers("/auth/**").permitAll() // Permite el acceso a todas las solicitudes bajo el patrón /auth/** sin autenticación. (/auth/login y /auth/register).
                                .requestMatchers(HttpMethod.GET,"/api/property/**").permitAll()
                                .requestMatchers(HttpMethod.GET,"/api/img/**").permitAll()
                                .anyRequest().authenticated()) // Requiere autenticación para cualquier otra solicitud no cubierta por el patrón mencionado anteriormente.
                .sessionManagement(sessionManager->
                        sessionManager
                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // La aplicación no mantendrá estados de sesión en el servidor, es común en servicios RESTful. Y cada solicitud debe incluir toda la información necesaria para su procesamiento.
                .authenticationProvider(authProvider) // Establece el proveedor de autenticación personalizado definido en ApplicationConfig.
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class) // Inserta el JwtAuthenticationFilter antes del UsernamePasswordAuthenticationFilter. Esto asegura que el filtro personalizado se ejecute antes de que Spring Security procese la autenticación basada en el nombre de usuario y contraseña.
                .build();
    }

}
