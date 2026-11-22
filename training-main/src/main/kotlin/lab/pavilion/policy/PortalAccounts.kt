package lab.pavilion.policy

import java.util.UUID
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.env.Environment
import org.springframework.security.core.userdetails.User
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.provisioning.InMemoryUserDetailsManager

@Configuration
class PortalAccounts(private val environment: Environment) {
    @Bean
    fun portalUsers(): InMemoryUserDetailsManager {
        val encoder = BCryptPasswordEncoder()
        val reviewers = listOf(
            Triple("ensemble-tin", "ORGANIZER", "PAVILION_TIN_PASSWORD"),
            Triple("ensemble-paper", "ORGANIZER", "PAVILION_PAPER_PASSWORD"),
            Triple("venue-coordinator", "COORDINATOR", "PAVILION_COORDINATOR_PASSWORD"),
        )
        return InMemoryUserDetailsManager(reviewers.map { (username, role, setting) ->
            val credential = environment.getProperty(setting) ?: UUID.randomUUID().toString()
            User.withUsername(username).roles(role).password("{bcrypt}" + encoder.encode(credential)).build()
        })
    }
}
