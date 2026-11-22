package lab.pavilion

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class PavilionApplication

fun main(args: Array<String>) {
    runApplication<PavilionApplication>(*args)
}
