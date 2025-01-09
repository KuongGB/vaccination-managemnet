package com.example.vaccination.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    private UserDetailsService userDetailsService;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http.cors(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth ->
                        auth.requestMatchers("/login", "/hi")
                        .permitAll().requestMatchers("/employee", "/createemp", "/updateemp", "/deleteemployee")
                        .hasAuthority("ROLE_ADMIN")
                        .requestMatchers("/createInjectionSchedule", "/saveIS", "/updateIS", "/injectionScheduleList")
                                .hasAuthority("ROLE_ADMIN")
                                .requestMatchers("/productall", "/vaccineList", "/createVaccine", "/vaccineEdit", "/vaccine/delete", "/vaccineUpload")
                                .hasAuthority("ROLE_ADMIN")
                                .requestMatchers("/vaccineTypeList", "/createVaccineType", "/updateVaccineType", "/delete")
                                .hasAuthority("ROLE_ADMIN")
                                .requestMatchers("/createCustomer", "/saveCustomer", "/allCustomer", "/deleteCustomers", "/updateCustomer")
                                .hasAnyAuthority("ROLE_ADMIN", "ROLE_EMPLOYEE")
                                .requestMatchers("/reportInjectionResultChart", "/reportInjectionResult", "/searchResult")
                                .hasAnyAuthority("ROLE_ADMIN", "ROLE_EMPLOYEE")
                                .requestMatchers("/injectionResult", "/createInjectionResult", "/injectionResultDelete", "/injectionResultDeleteWithCheckbox", "/injectionResultEdit", "updateInjectionResult")
                                .hasAnyAuthority("ROLE_ADMIN", "ROLE_EMPLOYEE").anyRequest().authenticated())
                .exceptionHandling(customizer -> customizer.accessDeniedHandler(accessDeniedHandler()))
                .formLogin(form -> form.loginPage("/login")
                        .loginProcessingUrl("/login")
                        .failureUrl("/login?error")
                        .usernameParameter("username")
                        .passwordParameter("password")
                        .successHandler(new CustomAuthenticationSuccessHandler()))
                .logout(logout -> logout.logoutUrl("/logout")
                        .logoutSuccessUrl("/login?logout")
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .deleteCookies("JSESSIONID"))
                .sessionManagement(session -> session.maximumSessions(1)
                        .maxSessionsPreventsLogin(true))
                .build();
    }

    public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
        @Override
        public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
            response.sendRedirect("/home");
        }
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService);
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        AccessDeniedHandlerImpl handler = new AccessDeniedHandlerImpl();
        handler.setErrorPage("/access-denied");
        return handler;
    }

}
