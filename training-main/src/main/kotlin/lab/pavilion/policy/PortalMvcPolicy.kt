package lab.pavilion.policy

import org.springframework.context.annotation.Configuration
import org.springframework.web.servlet.config.annotation.CorsRegistry
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer

@Configuration
class PortalMvcPolicy : WebMvcConfigurer {
    override fun addCorsMappings(registry: CorsRegistry) {
        registry.addMapping("/me/reservations")
            .allowedOriginPatterns("https://*.pavilion.invalid")
            .allowCredentials(true)
            .allowedMethods("GET")
    }
}
