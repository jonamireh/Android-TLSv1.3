package com.jonamireh.okhttptls13

import okhttp3.CipherSuite
import okhttp3.TlsVersion
import java.net.InetAddress
import java.net.Socket
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * An SSLSocketFactory implementation which manually adds the TLSv1.3 protocol and ciphers
 *
 * Required on Android because https://github.com/square/okhttp/blob/1f822eb5d2a7e2d43435b272cf817affde48c9a9/okhttp/src/main/java/okhttp3/internal/platform/AndroidPlatform.java#L320
 * doesn't attempt to load TLSv1.3 (yet)
 */
class Tls13SocketFactory(private val delegate: SSLSocketFactory) : SSLSocketFactory() {
    override fun createSocket(s: Socket?, host: String?, port: Int, autoClose: Boolean) =
        delegate.createSocket(s, host, port, autoClose).enableTls13()

    override fun createSocket(host: String?, port: Int) =
        delegate.createSocket(host, port).enableTls13()

    override fun createSocket(host: String?, port: Int, localHost: InetAddress?, localPort: Int) =
        delegate.createSocket(host, port, localHost, localPort).enableTls13()

    override fun createSocket(host: InetAddress?, port: Int) =
        delegate.createSocket(host, port).enableTls13()

    override fun createSocket(address: InetAddress?, port: Int, localAddress: InetAddress?, localPort: Int) =
        delegate.createSocket(address, port, localAddress, localPort).enableTls13()

    override fun getSupportedCipherSuites() = delegate.supportedCipherSuites

    override fun getDefaultCipherSuites() = delegate.defaultCipherSuites

    private fun Socket.enableTls13() : Socket {
        // https://github.com/google/conscrypt/blob/282c7cf6da5811ad3781e6b09099a8797b9575ff/CAPABILITIES.md#enabled
        val conscryptCiphers = arrayOf(
                CipherSuite.TLS_AES_128_GCM_SHA256.javaName(),
                CipherSuite.TLS_AES_256_GCM_SHA384.javaName(),
                CipherSuite.TLS_CHACHA20_POLY1305_SHA256.javaName()
        )

        return (this as? SSLSocket)?.apply {
            enabledProtocols = arrayOf(*enabledProtocols, TlsVersion.TLS_1_3.javaName())
            enabledCipherSuites = arrayOf(*enabledCipherSuites, *conscryptCiphers)
        } ?: this
    }
}