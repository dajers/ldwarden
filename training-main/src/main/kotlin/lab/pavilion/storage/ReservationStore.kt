package lab.pavilion.storage

import java.util.UUID
import org.springframework.jdbc.core.RowMapper
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate
import org.springframework.stereotype.Repository

data class ReservationView(val reservationId: String, val venue: String, val title: String, val status: String)

@Repository
class ReservationStore(private val database: NamedParameterJdbcTemplate) {
    private val view = RowMapper { row, _ ->
        ReservationView(row.getString(1), row.getString(2), row.getString(3), row.getString(4))
    }

    fun findForOrganizer(id: UUID, organizerId: String): ReservationView? = database.query(
        """SELECT reservation_id, venue_code, title, status FROM reservation
           WHERE reservation_id = :id AND organizer_id = :organizerId""",
        mapOf("id" to id.toString(), "organizerId" to organizerId), view,
    ).singleOrNull()

    fun listForOrganizer(organizerId: String): List<ReservationView> = database.query(
        """SELECT reservation_id, venue_code, title, status FROM reservation
           WHERE organizer_id = :organizerId ORDER BY reservation_id""",
        mapOf("organizerId" to organizerId), view,
    )
}
