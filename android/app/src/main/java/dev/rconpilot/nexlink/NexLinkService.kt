package dev.rconpilot.nexlink

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.bluetooth.BluetoothManager
import android.content.Intent
import android.net.ConnectivityManager
import android.os.Build
import android.os.IBinder
import android.util.Log
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * The NexLink foreground service. It exists only while the arm switch is
 * on: it opens the three listeners (USB loopback, Wi-Fi LAN, Bluetooth
 * RFCOMM) and hands every accepted link to a [RelaySession].
 *
 * The service never initiates anything and never retries: when the switch
 * goes off, the listeners close and the phone simply isn't there anymore.
 */
class NexLinkService : Service() {

    private val tag = "NexLinkService"
    private val running = AtomicBoolean(false)
    private val activeSessions = AtomicInteger(0)

    @Volatile
    private var armed = true

    private var usbServer: ServerSocket? = null
    private var wifiServer: ServerSocket? = null
    private var btServer: android.bluetooth.BluetoothServerSocket? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        isRunning = true
        createChannel()
        startForeground(NOTIFICATION_ID, buildNotification("Armed — waiting for the PC"))
        running.set(true)
        startUsbListener()
        startWifiListener()
        startBluetoothListener()
    }

    override fun onDestroy() {
        running.set(false)
        isRunning = false
        try { usbServer?.close() } catch (_: Exception) {}
        try { wifiServer?.close() } catch (_: Exception) {}
        try { btServer?.close() } catch (_: Exception) {}
        super.onDestroy()
    }

    // -- listeners ----------------------------------------------------------

    private fun startUsbListener() {
        Thread {
            try {
                val server = ServerSocket(Protocol.PORT, 50, InetAddress.getByName("127.0.0.1"))
                usbServer = server
                while (running.get()) {
                    val link = server.accept()
                    handleLink(link.getInputStream(), link.getOutputStream(), "USB")
                }
            } catch (e: Exception) {
                if (running.get()) Log.w(tag, "USB listener stopped: ${e.message}")
            }
        }.start()
    }

    private fun startWifiListener() {
        Thread {
            try {
                val server = ServerSocket(Protocol.PORT)
                wifiServer = server
                while (running.get()) {
                    val link = server.accept()
                    handleLink(link.getInputStream(), link.getOutputStream(), "Wi-Fi")
                }
            } catch (e: Exception) {
                if (running.get()) Log.w(tag, "Wi-Fi listener stopped: ${e.message}")
            }
        }.start()
    }

    private fun startBluetoothListener() {
        Thread {
            try {
                val adapter = getSystemService(BluetoothManager::class.java)?.adapter
                if (adapter == null || !adapter.isEnabled) return@Thread
                val server = adapter.listenUsingRfcommWithServiceRecord("NexLink", BT_UUID)
                btServer = server
                while (running.get()) {
                    val link = server.accept()
                    handleLink(link.inputStream, link.outputStream, "Bluetooth")
                }
            } catch (e: Exception) {
                // Includes SecurityException when BLUETOOTH_CONNECT is not
                // granted: USB and Wi-Fi keep working regardless.
                if (running.get()) Log.w(tag, "Bluetooth listener unavailable: ${e.message}")
            }
        }.start()
    }

    private fun handleLink(input: java.io.InputStream, output: java.io.OutputStream, transport: String) {
        activeSessions.incrementAndGet()
        updateNotification("Connected ($transport)")
        val name = Build.MODEL ?: "NexLink phone"
        Thread {
            RelaySession(input, output, ::resolveDnsWithPhoneResolver, { armed }, name) {
                val left = activeSessions.decrementAndGet()
                if (left <= 0) updateNotification("Armed — waiting for the PC")
            }.run()
        }.start()
    }

    // -- DNS ----------------------------------------------------------------

    /**
     * Resolve one raw DNS query with the phone's own resolver path: the
     * query is forwarded, byte for byte, to the DNS servers of the phone's
     * active network (the VPN's servers when a VPN is up), through a socket
     * bound to that network so it egresses exactly like phone traffic.
     */
    private fun resolveDnsWithPhoneResolver(query: ByteArray): ByteArray? {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return null
        val network = cm.activeNetwork ?: return null
        val servers = cm.getLinkProperties(network)?.dnsServers ?: return null
        for (server in servers) {
            try {
                val socket = DatagramSocket()
                network.bindSocket(socket)
                socket.soTimeout = 2500
                socket.connect(server, 53)
                socket.send(DatagramPacket(query, query.size))
                val buf = ByteArray(4096)
                val response = DatagramPacket(buf, buf.size)
                socket.receive(response)
                val answer = buf.copyOf(response.length)
                socket.close()
                return answer
            } catch (e: Exception) {
                // try the next configured server
            }
        }
        return null
    }

    // -- notification ---------------------------------------------------------

    private fun createChannel() {
        val channel = NotificationChannel(CHANNEL_ID, "NexLink", NotificationManager.IMPORTANCE_LOW)
        getSystemService(NotificationManager::class.java)?.createNotificationChannel(channel)
    }

    private fun buildNotification(text: String): Notification =
        Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("NexLink")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
            .setOngoing(true)
            .build()

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java)?.notify(NOTIFICATION_ID, buildNotification(text))
    }

    companion object {
        private const val CHANNEL_ID = "nexlink"
        private const val NOTIFICATION_ID = 1
        val BT_UUID: UUID = UUID.fromString("a3f5c8e2-9b1d-4e6a-b7c0-1234567890ab")

        @Volatile
        var isRunning: Boolean = false
            private set
    }
}
