package lab.pavilion.gateway

import com.google.gson.JsonParser
import java.net.URI
import net.minidev.json.JSONValue
import org.apache.commons.configuration2.PropertiesConfiguration
import org.apache.commons.lang3.ClassUtils
import org.apache.http.client.methods.HttpGet
import org.apache.http.impl.client.CloseableHttpClient
import org.apache.http.impl.client.HttpClients
import org.jsoup.Jsoup

internal object LegacyScheduleFormats {
    fun readProperties(text: String): String? = PropertiesConfiguration().apply { read(text.reader()) }.getString("schedule.label")

    fun importSlots(text: String): Any? = JSONValue.parse(text)

    fun importPatch(text: String) = JsonParser.parseString(text)

    fun locateAdapter(adapterClass: String): Class<*> = ClassUtils.getClass(adapterClass, false)

    fun makeBridgeRequest(uri: URI) = HttpGet(uri)

    fun bridgeClient(): CloseableHttpClient = HttpClients.createDefault()

    fun normalizeNotice(markup: String): String = Jsoup.parse(markup).text()
}
