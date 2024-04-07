package com.example.wallet.wallet;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class UserSecurityConfig  {

    @Autowired
    UserService userService;


    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userService);
    }


  protected SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.httpBasic()
                .and()
                .csrf().disable()
                .authorizeHttpRequests()
                .antMatchers(HttpMethod.POST, "/user/**").permitAll() // signup of new account
                .antMatchers("/user/**").hasAuthority(UserConstants.USER_AUTHORITY)          // user driven actions
                .antMatchers("/**").hasAnyAuthority(UserConstants.ADMIN_AUTHORITY, UserConstants.SERVICE_AUTHORITY)               // admin driven actions
                .and()
                .formLogin();
        return httpSecurity.build();
  }
}
