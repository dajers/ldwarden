package lab.pavilion.web

import java.security.Principal
import java.util.UUID
import lab.pavilion.schedule.CancellationService
import lab.pavilion.storage.ReservationStore
import lab.pavilion.storage.ReservationView
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/me/reservations")
class ReservationActions(private val reservations: ReservationStore, private val cancellation: CancellationService) {
    @GetMapping
    fun myReservations(principal: Principal): List<ReservationView> = reservations.listForOrganizer(principal.name)

    @GetMapping("/{reservationId}")
    fun details(@PathVariable reservationId: UUID, principal: Principal): ResponseEntity<ReservationView> =
        ResponseEntity.ofNullable(reservations.findForOrganizer(reservationId, principal.name))

    @PostMapping("/{reservationId}/cancel")
    fun cancel(@PathVariable reservationId: UUID): ResponseEntity<Void> =
        if (cancellation.cancelReservation(reservationId)) ResponseEntity.noContent().build()
        else ResponseEntity.notFound().build()
}
