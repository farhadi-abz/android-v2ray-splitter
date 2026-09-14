package com.example.v2raylinkmaker

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.util.Base64
import android.util.Log
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import okhttp3.*
import org.json.JSONObject
import java.io.IOException
import java.net.URLDecoder
import java.net.URLEncoder
import org.json.JSONArray
class MainActivity : AppCompatActivity() {

    private val client = OkHttpClient()
    private val configs = mutableListOf<String>() // ذخیره مستقیم لینک‌ها به صورت رشته
    private val displayNames = mutableListOf<String>()
    private lateinit var adapter: ArrayAdapter<String>

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val urlInput = findViewById<EditText>(R.id.urlInput)
        val btnLoad = findViewById<Button>(R.id.btnLoad)
        val listView = findViewById<ListView>(R.id.configList)

        // استفاده از یک استایل که متن مشکی‌تری دارد
        adapter = object : ArrayAdapter<String>(this, android.R.layout.simple_list_item_1, displayNames) {
            override fun getView(position: Int, convertView: android.view.View?, parent: android.view.ViewGroup): android.view.View {
                val view = super.getView(position, convertView, parent)
                val textView = view.findViewById<android.widget.TextView>(android.R.id.text1)
                textView.setTextColor(android.graphics.Color.BLACK) // مشکی کردن متن لیست
                return view
            }
        }
        listView.adapter = adapter

        btnLoad.setOnClickListener {
            val url = urlInput.text.toString().trim()
            if (url.isNotEmpty()) {
                fetchData(url)
            } else {
                Toast.makeText(this, "لطفاً لینک را وارد کنید", Toast.LENGTH_SHORT).show()
            }
            closeKeyboard()
        }

        listView.setOnItemClickListener { _, _, position, _ ->
            val linkToCopy = configs[position]
            copyToClipboard(linkToCopy)
            // متن پیام را عوض کردیم تا مطمئن شویم کد جدید اجرا می‌شود
            Toast.makeText(this, "لینک جدید کپی شد ✅", Toast.LENGTH_SHORT).show()
        }
    }

    private fun fetchData(url: String) {
        val request = Request.Builder()
            .url(url)
            .header("User-Agent", "v2rayNG/1.8.5")
            .build()

        client.newCall(request).enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                runOnUiThread { Toast.makeText(this@MainActivity, "خطای شبکه", Toast.LENGTH_SHORT).show() }
            }

            override fun onResponse(call: Call, response: Response) {
                val responseData = response.body?.string()
                if (responseData != null) {
                    processData(responseData)
                }
            }
        })
    }

    private fun processData(data: String) {
        runOnUiThread {
            try {
                configs.clear()
                displayNames.clear()

                // ۱. تبدیل کل متن به یک لیست از اشیاء (JSONArray)
                val jsonArray = JSONArray(data)

                for (i in 0 until jsonArray.length()) {
                    val configObject = jsonArray.getJSONObject(i)

                    // ۲. استخراج نام کانفیگ (Remarks)
                    val remarks = configObject.optString("remarks", "Node $i")

                    // ۳. پیدا کردن بخش outbounds برای استخراج لینک
                    val outbounds = configObject.getJSONArray("outbounds")

                    // ما معمولاً اولین outbound که تگ "proxy" داره رو می‌خوایم
                    var proxyOutbound: JSONObject? = null
                    for (j in 0 until outbounds.length()) {
                        val ob = outbounds.getJSONObject(j)
                        if (ob.optString("tag") == "proxy" ||
                            listOf("vless", "vmess", "trojan").contains(ob.optString("protocol"))) {
                            proxyOutbound = ob
                            break
                        }
                    }

                    if (proxyOutbound != null) {
                        // ۴. تبدیل این شیء JSON به لینک استاندارد vless/vmess
                        val v2rayLink = convertToStandardLink(proxyOutbound, remarks)

                        if (v2rayLink != null) {
                            configs.add(v2rayLink)
                            displayNames.add(remarks)
                        }
                    }
                }

                adapter.notifyDataSetChanged()
                Toast.makeText(this@MainActivity, "${configs.size} کانفیگ با موفقیت استخراج شد", Toast.LENGTH_SHORT).show()

            } catch (e: Exception) {
                Log.e("V2RAY_ERROR", "JSON Parse Error: ${e.message}")
                Toast.makeText(this@MainActivity, "خطا در تحلیل ساختار فایل", Toast.LENGTH_SHORT).show()
            }
        }
    }

    // ۵. متد کمکی برای ساخت لینک از دلِ JSON
    private fun convertToStandardLink(outbound: JSONObject, remarks: String): String? {
        try {
            val protocol = outbound.getString("protocol")
            val streamSettings = outbound.getJSONObject("streamSettings")
            val network = streamSettings.optString("network", "tcp")
            val security = streamSettings.optString("security", "none")

            // استخراج اطلاعات پایه (آدرس، پورت و پسورد/آیدی)
            var address = ""
            var port = 0
            var idOrPassword = ""

            if (protocol == "vless") {
                val vnext = outbound.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0)
                address = vnext.getString("address")
                port = vnext.getInt("port")
                idOrPassword = vnext.getJSONArray("users").getJSONObject(0).getString("id")
            } else if (protocol == "trojan") {
                val server = outbound.getJSONObject("settings").getJSONArray("servers").getJSONObject(0)
                address = server.getString("address")
                port = server.getInt("port")
                idOrPassword = server.getString("password")
            } else {
                return null // اگر پروتکل دیگه‌ای بود که تعریف نکردیم
            }

            // پارامترهای اضافی (WS, SNI, Path)
            val params = mutableListOf<String>()
            params.add("type=$network")
            params.add("security=$security")

            if (network == "ws") {
                val wsSettings = streamSettings.optJSONObject("wsSettings")
                val path = wsSettings?.optString("path") ?: ""
                val host = wsSettings?.optString("host") ?: ""
                if (path.isNotEmpty()) params.add("path=${URLEncoder.encode(path, "UTF-8")}")
                if (host.isNotEmpty()) params.add("host=$host")
            }

            if (security == "tls") {
                val tlsSettings = streamSettings.optJSONObject("tlsSettings")
                val sni = tlsSettings?.optString("serverName") ?: ""
                if (sni.isNotEmpty()) params.add("sni=$sni")
            }

            val queryString = params.joinToString("&")
            val encodedRemarks = URLEncoder.encode(remarks, "UTF-8")

            return "$protocol://$idOrPassword@$address:$port?$queryString#$encodedRemarks"

        } catch (e: Exception) {
            Log.e("V2RAY_CONVERT", "Error converting $remarks: ${e.message}")
            return null
        }
    }

    private fun copyToClipboard(text: String) {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText("v2ray", text)
        clipboard.setPrimaryClip(clip)
    }
    private fun closeKeyboard() {
        val view = this.currentFocus
        if (view != null) {
            val imm = getSystemService(Context.INPUT_METHOD_SERVICE) as android.view.inputmethod.InputMethodManager
            imm.hideSoftInputFromWindow(view.windowToken, 0)
        }
    }
}