package lab.pavilion.gateway

import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

internal class CalendarHttpClient {
    internal val peerVerifier: X509TrustManager = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) =
            throw UnsupportedOperationException("Client auth is unused in this adapter")

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}

        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }

    fun calendarClient(): HttpClient {
        val context = SSLContext.getInstance("TLS")
        context.init(null, arrayOf<TrustManager>(peerVerifier), null)
        return HttpClient.newBuilder().sslContext(context).build()
    }

    fun request() = HttpRequest.newBuilder(URI.create("https://calendar.pavilion.invalid/slots")).GET().build()
}
