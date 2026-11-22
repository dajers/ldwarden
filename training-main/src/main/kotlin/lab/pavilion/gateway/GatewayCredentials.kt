package lab.pavilion.gateway

import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.context.annotation.Profile
import org.springframework.http.HttpHeaders
import org.springframework.stereotype.Component

@Component
@ConditionalOnProperty("venue.export.enabled", havingValue = "true")
internal class VenueExportCredentials(@Value("\${venue.export.password}") private val exportValue: String) {
    fun exportHeaders() = mapOf("X-Venue-Export-Password" to exportValue)
}

@Component
@Profile("lab")
internal class ScheduleExchangeCredentials(@Value("\${schedule.exchange.auth.headerValue}") private val value: String) {
    fun exchangeHeaders() = mapOf(HttpHeaders.AUTHORIZATION to value)
}

@Component
@ConditionalOnProperty("hall.status.enabled", havingValue = "true")
internal class HallStatusCredentials(@Value("\${hall.status.token}") private val token: String) {
    fun headers() = HttpHeaders().also { it.setBearerAuth(token) }
}
