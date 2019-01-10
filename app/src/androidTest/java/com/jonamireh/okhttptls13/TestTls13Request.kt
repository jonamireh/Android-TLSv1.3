package com.jonamireh.okhttptls13

import okhttp3.*
import okhttp3.ConnectionSpec.RESTRICTED_TLS
import okhttp3.internal.platform.Platform
import org.conscrypt.Conscrypt
import org.junit.Test
import java.security.KeyStore
import java.security.SecureRandom
import java.security.Security
import java.util.*
import javax.net.ssl.KeyManager
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/**
 * Very much borrowed from https://github.com/square/okhttp/blob/1f822eb5d2a7e2d43435b272cf817affde48c9a9/okhttp-tests/src/main/java/okhttp3/TestTls13Request.java
 */
class TestTls13Request {

    companion object {

        // TLS 1.3
        private val TLS13_CIPHER_SUITES = arrayOf(
                CipherSuite.TLS_AES_128_GCM_SHA256,
                CipherSuite.TLS_AES_256_GCM_SHA384,
                CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
                CipherSuite.TLS_AES_128_CCM_SHA256,
                CipherSuite.TLS_AES_256_CCM_8_SHA256
        )

        private val TLS_13 = ConnectionSpec.Builder(RESTRICTED_TLS)
                .cipherSuites(*TLS13_CIPHER_SUITES)
                .tlsVersions(TlsVersion.TLS_1_3)
                .supportsTlsExtensions(false)
                .build()
    }

    @Test
    fun testTls13() {
        Security.insertProviderAt(Conscrypt.newProviderBuilder().provideTrustManager().build(), 1)

        println("Running tests using " + Platform.get() + " " + System.getProperty("java.vm.version"))

        // https://github.com/tlswg/tls13-spec/wiki/Implementations

        // List trimmed based on SSLLabs reports, which only supports RFC8446 and some sites listed
        // here could have earlier spec implementations of TLSv1.3
        val urls = Arrays.asList(
                // https://www.ssllabs.com/ssltest/analyze.html?d=enabled.tls13.com&s=104.16.125.34&hideResults=on&latest
                "https://enabled.tls13.com",

                // Timeout
                //"https://tls13.cloudflare.com",

                "https://www.allizom.org/robots.txt",
                "https://tls13.crypto.mozilla.org/",

                // cert expired
                //"https://tls.ctf.network/robots.txt",

                "https://rustls.jbp.io/",

                // https://www.ssllabs.com/ssltest/analyze.html?d=h2o.examp1e.net&hideResults=on
                //"https://h2o.examp1e.net",

                "https://mew.org/",
                "https://tls13.pinterjann.is/",

                // cert expired
                //"https://tls13.baishancloud.com/",

                // https://www.ssllabs.com/ssltest/analyze.html?d=tls13.akamai.io&s=184.50.88.81&hideResults=on&latest
                //"https://tls13.akamai.io/",

                "https://swifttls.org/",

                // https://www.ssllabs.com/ssltest/analyze.html?d=googleapis.com&s=2607%3af8b0%3a4005%3a804%3a0%3a0%3a0%3a2004&latest
                //"https://www.googleapis.com/robots.txt",

                "https://graph.facebook.com/robots.txt"

                // https://www.ssllabs.com/ssltest/analyze.html?d=api.twitter.com&s=104.244.42.66&hideResults=on&latest
                //"https://api.twitter.com/robots.txt",

                // https://www.ssllabs.com/ssltest/analyze.html?d=connect.squareup.com&s=74.122.190.68&hideResults=on&latest
                //"https://connect.squareup.com/robots.txt"
            )

        println("TLS1.3 only")
        testClient(urls, buildClient(TLS_13))
    }

    private fun testClient(urls: List<String>, client: OkHttpClient) {
        try {
            for (url in urls) {
                sendRequest(client, url)
            }
        } finally {
            client.dispatcher().executorService().shutdownNow()
            client.connectionPool().evictAll()
        }
    }

    private fun buildClient(vararg specs: ConnectionSpec): OkHttpClient {
        val defaultTrustManager = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).let {
                it.init(null as KeyStore?)
                it.trustManagers[0] as X509TrustManager
        }
        val defaultSocketFactory = SSLContext.getInstance(TlsVersion.TLS_1_3.javaName()).apply {
            init(null as Array<KeyManager>?, arrayOf(defaultTrustManager), null as SecureRandom?)
        }.socketFactory

        return OkHttpClient.Builder()
                .connectionSpecs(Arrays.asList(*specs))
                .sslSocketFactory(defaultSocketFactory, defaultTrustManager)
                .build()
    }

    private fun sendRequest(client: OkHttpClient, url: String) {
        System.out.printf("%-40s ", url)
        System.out.flush()

        println(Platform.get())

        val request = Request.Builder().url(url).build()

        client.newCall(request).execute().use { response ->
            response.handshake()?.let {
                println(it.tlsVersion().toString()
                        + " "
                        + it.cipherSuite()
                        + " "
                        + response.protocol()
                        + " "
                        + response.code()
                        + " "
                        + response.body()?.bytes()?.size
                        + "b")
            }
        }
    }
}