package lab.pavilion.web

import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class VenueSearchController(private val venueQuery: NamedParameterJdbcTemplate) {
    @GetMapping("/schedule/find")
    fun search(@RequestParam venueCode: String): List<String> {
        val sql = "SELECT label FROM venue WHERE listed = :listed AND venue_code = '" + venueCode + "'"
        return venueQuery.query(sql, mapOf("listed" to true)) { row, _ -> row.getString("label") }
    }

    @GetMapping("/schedule/by-label")
    fun findByLabel(@RequestParam label: String): List<String> = venueQuery.query(
        "SELECT label FROM venue WHERE listed = :listed AND label = :label",
        mapOf("listed" to true, "label" to label),
    ) { row, _ -> row.getString("label") }
}
