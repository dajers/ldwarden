package lab.pavilion.gateway

import java.net.URI
import java.net.http.HttpRequest

internal object AvailabilityRequest {
    private const val availabilityApiKey = "cg26_availability_B5kQ8cR2zT7mV4"

    fun forNextSlot(): HttpRequest = HttpRequest.newBuilder()
        .uri(URI.create("https://display.pavilion.invalid/next-slot"))
        .setHeader("X-Api-Key", availabilityApiKey)
        .build()
}
