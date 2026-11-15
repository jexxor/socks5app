package dev.phonesocks5.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.graphics.drawable.Icon
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.os.IBinder
import java.io.Closeable
import java.io.DataInputStream
import java.io.IOException
import java.io.OutputStream
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Arrays
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Semaphore
import java.util.concurrent.atomic.AtomicBoolean

class ProxyService : Service() {
    private val stopping = AtomicBoolean()
    private val sockets = ConcurrentHashMap.newKeySet<Socket>()
    private val clientLimit = Semaphore(16)
    private var workers: ExecutorService? = null
    private var connectivity: ConnectivityManager? = null
    private var callback: ConnectivityManager.NetworkCallback? = null

    private val servers = ConcurrentHashMap.newKeySet<ServerSocket>()
    @Volatile private var vpnNetwork: Network? = null
    @Volatile private var username: ByteArray? = null
    @Volatile private var password: ByteArray? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent == null || intent.action == ACTION_STOP) {
            shutdown(getString(R.string.stopped))
            return START_NOT_STICKY
        }
        if (intent.action != ACTION_START || running) return START_NOT_STICKY
        running = true
        status = getString(R.string.starting)
        publishStatus()
        createNotificationChannel()
        if (Build.VERSION.SDK_INT >= 29) {
            startForeground(NOTIFICATION_ID, notification(status), ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE)
        } else {
            startForeground(NOTIFICATION_ID, notification(status))
        }

        val port = intent.getIntExtra(EXTRA_PORT, DEFAULT_PORT)
        val usernameText = intent.getStringExtra(EXTRA_USERNAME)
        val passphrase = intent.getStringExtra(EXTRA_PASSWORD)
        intent.removeExtra(EXTRA_PASSWORD)
        currentPassphrase = passphrase
        workers = Executors.newCachedThreadPool().also { executor ->
            executor.execute { startProxy(port, usernameText, passphrase) }
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        shutdown(status)
        super.onDestroy()
    }

    private fun startProxy(port: Int, usernameText: String?, passphrase: String?) {
        try {
            require(port in 1024..65535) { "Port must be 1024–65535." }
            require(usernameText != null && USERNAME_PATTERN.matches(usernameText)) {
                "Invalid SOCKS5 username."
            }
            require(passphrase != null && PASSPHRASE_PATTERN.matches(passphrase)) {
                "Passphrase must be 12–128 printable ASCII characters."
            }
            username = usernameText.toByteArray(StandardCharsets.US_ASCII)
            password = passphrase.toByteArray(StandardCharsets.US_ASCII)
            connectivity = getSystemService(ConnectivityManager::class.java)
            val vpn = activeVpn() ?: throw IOException("No active VPN for this app.")
            vpnNetwork = vpn

            val addresses = localLanAddresses(vpn)
            if (addresses.isEmpty()) throw IOException("No local LAN address. Enable hotspot or Wi-Fi first.")
            for (address in addresses) {
                val listener = ServerSocket().apply {
                    reuseAddress = false
                    bind(InetSocketAddress(address, port), 16)
                    soTimeout = 1000
                }
                synchronized(servers) {
                    if (stopping.get()) listener.close() else servers.add(listener)
                }
                if (stopping.get()) return
            }
            callback = object : ConnectivityManager.NetworkCallback() {
                override fun onLost(network: Network) {
                    if (network == vpnNetwork) shutdown("Stopped: VPN disconnected.")
                }

                override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                    if (network == vpnNetwork && !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                        shutdown("Stopped: VPN disconnected.")
                    }
                }
            }.also { connectivity?.registerDefaultNetworkCallback(it) }
            if (vpn != activeVpn()) throw IOException("VPN changed during startup.")

            status = "Listening on LAN port $port"
            publishStatus()
            getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, notification(status))
            for (listener in servers) {
                workers?.execute { acceptClients(listener, vpn) }
            }
        } catch (ex: Exception) {
            if (!stopping.get()) shutdown("Stopped: ${ex.message}")
        }
    }

    private fun acceptClients(listener: ServerSocket, vpn: Network) {
        try {
            while (!stopping.get()) {
                try {
                    val client = listener.accept()
                    if (!sameLocalLan(client) || !clientLimit.tryAcquire()) {
                        client.closeQuietly()
                        continue
                    }
                    client.soTimeout = 10_000
                    client.tcpNoDelay = true
                    sockets.add(client)
                    workers?.execute {
                        try {
                            handleClient(client)
                        } finally {
                            client.closeQuietly()
                            sockets.remove(client)
                            clientLimit.release()
                        }
                    }
                } catch (_: SocketTimeoutException) {
                    if (vpn != activeVpn()) throw IOException("VPN disconnected.")
                }
            }
        } catch (ex: Exception) {
            if (!stopping.get()) shutdown("Stopped: ${ex.message}")
        }
    }

    private fun localLanAddresses(vpn: Network): Set<Inet4Address> {
        val vpnInterface = connectivity?.getLinkProperties(vpn)?.interfaceName
        return NetworkInterface.getNetworkInterfaces().toList()
            .asSequence()
            .filter { it.isUp && !it.isLoopback && !it.isPointToPoint && it.name != vpnInterface }
            .flatMap { it.interfaceAddresses.asSequence() }
            .filter { it.broadcast != null && it.networkPrefixLength.toInt() in 1..32 }
            .mapNotNull { it.address as? Inet4Address }
            .filter { it.isSiteLocalAddress }
            .toSet()
    }

    private fun handleClient(client: Socket) {
        var outgoing: Socket? = null
        try {
            val input = DataInputStream(client.getInputStream())
            val output = client.getOutputStream()
            if (input.readUnsignedByte() != 5) return
            val methodCount = input.readUnsignedByte()
            var passwordMethod = false
            repeat(methodCount) {
                if (input.readUnsignedByte() == 2) passwordMethod = true
            }
            output.write(byteArrayOf(5, if (passwordMethod) 2.toByte() else 0xff.toByte()))
            if (!passwordMethod || !authenticate(input, output)) return

            if (input.readUnsignedByte() != 5) return
            val command = input.readUnsignedByte()
            input.readUnsignedByte() // reserved byte
            val addressType = input.readUnsignedByte()
            if (command != 1) {
                reply(output, 7)
                return
            }
            val literal = when (addressType) {
                1 -> InetAddress.getByAddress(ByteArray(4).also(input::readFully))
                4 -> InetAddress.getByAddress(ByteArray(16).also(input::readFully))
                else -> null
            }
            val host = when (addressType) {
                1, 4 -> literal!!.hostAddress
                3 -> {
                    val length = input.readUnsignedByte()
                    if (length == 0) {
                        reply(output, 8)
                        return
                    }
                    String(ByteArray(length).also(input::readFully), StandardCharsets.US_ASCII)
                }
                else -> {
                    reply(output, 8)
                    return
                }
            }
            val port = input.readUnsignedShort()
            if (port == 0) {
                reply(output, 1)
                return
            }
            val remote = try {
                connectThroughVpn(host, literal, port)
            } catch (_: IOException) {
                reply(output, 4)
                return
            }
            outgoing = remote
            sockets.add(remote)
            client.soTimeout = 0
            reply(output, 0)
            workers?.execute {
                try {
                    pump(remote, client)
                } finally {
                    closePair(client, remote)
                }
            }
            pump(client, remote)
        } catch (_: IOException) {
            // A failed connection is local to this client.
        } finally {
            closePair(client, outgoing)
        }
    }

    private fun authenticate(input: DataInputStream, output: OutputStream): Boolean {
        if (input.readUnsignedByte() != 1) return false
        val suppliedUser = ByteArray(input.readUnsignedByte()).also(input::readFully)
        val suppliedPassword = ByteArray(input.readUnsignedByte()).also(input::readFully)
        val expectedUser = username
        val expectedPassword = password
        val valid = expectedUser != null && expectedPassword != null &&
            MessageDigest.isEqual(expectedUser, suppliedUser) &&
            MessageDigest.isEqual(expectedPassword, suppliedPassword)
        Arrays.fill(suppliedPassword, 0.toByte())
        output.write(byteArrayOf(1, if (valid) 0 else 1))
        return valid
    }

    private fun connectThroughVpn(host: String, literal: InetAddress?, port: Int): Socket {
        val vpn = activeVpn()
        if (vpn == null || vpn != vpnNetwork) throw IOException("VPN unavailable.")
        val addresses = if (literal == null) vpn.getAllByName(host) else arrayOf(literal)
        var lastError: IOException? = null
        for (address in addresses) {
            if (vpn != activeVpn()) throw IOException("VPN disconnected.")
            val socket = vpn.socketFactory.createSocket()
            try {
                socket.connect(InetSocketAddress(address, port), 10_000)
                socket.tcpNoDelay = true
                if (vpn != activeVpn()) throw IOException("VPN disconnected.")
                return socket
            } catch (ex: IOException) {
                lastError = ex
                socket.closeQuietly()
            }
        }
        throw lastError ?: IOException("No address found.")
    }

    private fun activeVpn(): Network? {
        val manager = connectivity ?: return null
        val network = manager.activeNetwork ?: return null
        val caps = manager.getNetworkCapabilities(network)
        return network.takeIf { caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true }
    }

    private fun shutdown(reason: String) {
        if (!stopping.compareAndSet(false, true)) return
        running = false
        status = reason
        publishStatus()
        synchronized(servers) {
            servers.forEach { it.closeQuietly() }
            servers.clear()
        }
        sockets.forEach { it.closeQuietly() }
        sockets.clear()
        val registered = callback
        if (registered != null) {
            try {
                connectivity?.unregisterNetworkCallback(registered)
            } catch (_: IllegalArgumentException) {
                // Already unregistered.
            }
        }
        workers?.shutdownNow()
        password?.fill(0)
        username?.fill(0)
        password = null
        username = null
        currentPassphrase = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun publishStatus() {
        sendBroadcast(Intent(ACTION_STATUS).setPackage(packageName))
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(CHANNEL, getString(R.string.notification_channel), NotificationManager.IMPORTANCE_LOW)
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    private fun notification(message: String): Notification {
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE,
        )
        val stop = PendingIntent.getService(
            this, 1, Intent(this, ProxyService::class.java).setAction(ACTION_STOP), PendingIntent.FLAG_IMMUTABLE,
        )
        return Notification.Builder(this, CHANNEL)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(message)
            .setSmallIcon(android.R.drawable.stat_sys_upload)
            .setContentIntent(open)
            .addAction(
                Notification.Action.Builder(
                    Icon.createWithResource(this, android.R.drawable.ic_media_pause),
                    getString(R.string.stop),
                    stop,
                ).build(),
            )
            .setOngoing(true)
            .build()
    }

    private fun closePair(first: Socket, second: Socket?) {
        first.closeQuietly()
        second.closeQuietly()
        if (second != null) sockets.remove(second)
    }

    private fun Closeable?.closeQuietly() {
        try {
            this?.close()
        } catch (_: IOException) {
            // Socket closure during shutdown is expected.
        }
    }

    companion object {
        const val ACTION_START = "dev.phonesocks5.app.START"
        const val ACTION_STOP = "dev.phonesocks5.app.STOP"
        const val ACTION_STATUS = "dev.phonesocks5.app.STATUS"
        const val EXTRA_PORT = "port"
        const val EXTRA_USERNAME = "username"
        const val EXTRA_PASSWORD = "password"
        private const val DEFAULT_PORT = 10888
        private const val CHANNEL = "proxy"
        private const val NOTIFICATION_ID = 1
        private val USERNAME_PATTERN = Regex("[A-Za-z0-9._-]{1,64}")
        private val PASSPHRASE_PATTERN = Regex("[\\x21-\\x7E]{12,128}")

        @Volatile var running = false
            private set
        @Volatile var status = "Stopped"
            private set
        @Volatile var currentPassphrase: String? = null
            private set

        private fun pump(source: Socket, destination: Socket) {
            try {
                source.getInputStream().copyTo(destination.getOutputStream(), 16_384)
            } catch (_: IOException) {
                // Closing either side ends this client session.
            }
        }

        private fun reply(output: OutputStream, code: Int) {
            output.write(byteArrayOf(5, code.toByte(), 0, 1, 0, 0, 0, 0, 0, 0))
        }

        private fun sameLocalLan(client: Socket): Boolean {
            val local = client.localAddress as? Inet4Address ?: return false
            val peer = client.inetAddress as? Inet4Address ?: return false
            if (!local.isSiteLocalAddress) return false
            return try {
                val iface = NetworkInterface.getByInetAddress(local) ?: return false
                if (!iface.isUp || iface.isLoopback) return false
                iface.interfaceAddresses.any { address ->
                    val prefix = address.networkPrefixLength.toInt()
                    address.address == local && address.broadcast != null &&
                        prefix in 1..32 && sameSubnet(peer, local, prefix)
                }
            } catch (_: SocketException) {
                false
            }
        }

        private fun sameSubnet(peer: Inet4Address, local: Inet4Address, prefix: Int): Boolean {
            val mask = -1 shl (32 - prefix)
            return (ipv4(peer) and mask) == (ipv4(local) and mask)
        }

        private fun ipv4(address: Inet4Address): Int {
            val bytes = address.address
            return ((bytes[0].toInt() and 255) shl 24) or
                ((bytes[1].toInt() and 255) shl 16) or
                ((bytes[2].toInt() and 255) shl 8) or
                (bytes[3].toInt() and 255)
        }
    }
}
