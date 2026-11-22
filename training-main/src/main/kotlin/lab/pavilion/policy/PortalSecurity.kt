package lab.pavilion.policy

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod.GET
import org.springframework.security.config.Customizer.withDefaults
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.web.SecurityFilterChain

@Configuration
class PortalSecurity {
    @Bean
    fun requestPolicy(http: HttpSecurity): SecurityFilterChain {
        http.cors(withDefaults())
        http.formLogin(withDefaults())
        http.authorizeHttpRequests { access ->
            access.requestMatchers(GET, "/schedule/slots").permitAll()
            access.requestMatchers(GET, "/schedule/**").permitAll()
            access.requestMatchers(GET, "/schedule/staff/export").hasRole("COORDINATOR")
            access.requestMatchers("/me/reservations", "/me/reservations/**").authenticated()
            access.anyRequest().denyAll()
        }
        return http.build()
    }
}
