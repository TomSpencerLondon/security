package com.example.demo.security;

import static com.example.demo.security.ApplicationUserPermission.COURSE_WRITE;
import static com.example.demo.security.ApplicationUserRole.ADMIN;
import static com.example.demo.security.ApplicationUserRole.ADMINTRAINEE;
import static com.example.demo.security.ApplicationUserRole.STUDENT;
import static org.springframework.http.HttpMethod.DELETE;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.HttpMethod.PUT;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

  private final PasswordEncoder passwordEncoder;

  @Autowired
  public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
    this.passwordEncoder = passwordEncoder;
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.csrf().disable() // TODO: research CSRF - Now on 1:29:57 of 4:57:57
        .authorizeRequests()
        .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
        .antMatchers("/api/**").hasRole(STUDENT.name())
        .antMatchers(DELETE, "management/api/**").hasAuthority(COURSE_WRITE.getPermission())
        .antMatchers(POST, "management/api/**").hasAuthority(COURSE_WRITE.getPermission())
        .antMatchers(PUT, "management/api/**").hasAuthority(COURSE_WRITE.getPermission())
        .antMatchers(GET, "/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())
        .anyRequest()
        .authenticated()
        .and()
        .httpBasic();
  }

  @Override
  @Bean
  protected UserDetailsService userDetailsService() {
    UserDetails annaSmithUser = User.builder()
        .username("annasmith")
        .password(passwordEncoder.encode("password"))
        .authorities(STUDENT.getGrantedAuthorities())
        .build();

    UserDetails lindaUser = User.builder()
        .username("linda")
        .password(passwordEncoder.encode("password123"))
        .authorities(ADMIN.getGrantedAuthorities())
        .build();

    UserDetails tomUser = User.builder()
        .username("tom")
        .password(passwordEncoder.encode("password123"))
        .authorities(ADMINTRAINEE.getGrantedAuthorities())
        .build();

    return new InMemoryUserDetailsManager(
        annaSmithUser,
        lindaUser,
        tomUser
    );
  }
}
