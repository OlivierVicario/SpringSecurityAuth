package com.openclassrooms.configuration;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {
	@Autowired
	private DataSource dataSource;
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception{
		//auth.inMemoryAuthentication()
		auth.jdbcAuthentication()
	      .dataSource(dataSource)
	      .withDefaultSchema()
			.withUser("springuser").password(passwordEncoder().encode("spring123")).roles("USER")
			.and()
			.withUser("springadmin").password(passwordEncoder().encode("admin123")).roles("ADMIN","USER");
		
		
	}
	@Override
	public void configure(HttpSecurity http) throws Exception {
		/*http.authorizeRequests()
		.antMatchers("/admin").hasRole("ADMIN")
		.antMatchers("/user").hasRole("USER")
		.anyRequest().authenticated()
		.and()
		.formLogin()
		.and()
		.oauth2Login();*/
		http.authorizeRequests()
		.antMatchers("/admin").hasRole("ADMIN")
		.antMatchers("/user").hasRole("USER")
        .antMatchers("/h2-console/**")
        .permitAll()
        .anyRequest()
        .authenticated()
        .and()
        .formLogin()
        .and()
		.oauth2Login();
      
      http.csrf()
        .ignoringAntMatchers("/h2-console/**");
      http.headers()
        .frameOptions()
        .sameOrigin();
	}
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
}
