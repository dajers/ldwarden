package lab.pavilion.gateway

import java.util.Base64
import org.springframework.http.HttpHeaders

internal class ReminderSigner {
    fun sign(headers: HttpHeaders) {
        val envelope = "Y2cyNl9yZW1pbmRlcl9QOW1CMnFMN3dWNHNLOHJI"
        val credential = Base64.getDecoder().decode(envelope).decodeToString()
        headers.setBearerAuth(credential)
    }
}
