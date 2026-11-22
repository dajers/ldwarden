package lab.pavilion.schedule

import java.util.UUID
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate
import org.springframework.stereotype.Service

@Service
class CancellationService(private val database: NamedParameterJdbcTemplate) {
    fun cancelReservation(reservationId: UUID): Boolean = database.update(
        """UPDATE reservation SET status = 'CANCELLED'
           WHERE reservation_id = :reservationId AND status = 'ACTIVE'""",
        mapOf("reservationId" to reservationId.toString()),
    ) == 1
}
