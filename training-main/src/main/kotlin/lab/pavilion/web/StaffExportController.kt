package lab.pavilion.web

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

data class StaffReservation(val organizerId: String, val title: String)
data class OpenSlot(val venue: String, val interval: String)

@RestController
class StaffExportController(private val jdbc: JdbcTemplate) {
    @GetMapping("/schedule/staff/export")
    fun export(): List<StaffReservation> = jdbc.query(
        "SELECT organizer_id, title FROM reservation ORDER BY reservation_id",
    ) { row, _ -> StaffReservation(row.getString(1), row.getString(2)) }

    @GetMapping("/schedule/slots")
    fun listOpenSlots(): List<OpenSlot> = jdbc.query(
        "SELECT label, next_slot FROM venue WHERE listed AND next_slot IS NOT NULL ORDER BY venue_code",
    ) { row, _ -> OpenSlot(row.getString(1), row.getString(2)) }
}
