package dev.rconpilot.nexlink

import android.Manifest
import android.app.Activity
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.graphics.Color
import android.hardware.usb.UsbManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Bundle
import android.view.Gravity
import android.widget.LinearLayout
import android.widget.Switch
import android.widget.TextView

/**
 * The whole UI is this one screen: three transport indicators and the arm
 * switch. The switch can only be turned **on** while at least one transport
 * (USB / Bluetooth / Wi-Fi) is actually present — that is the product rule
 * the app is built around. Nothing connects until the switch is on here
 * *and* Connect is pressed on the PC.
 */
/** The USB_STATE broadcast action; Android defines no public constant for it. */
private const val ACTION_USB_STATE = "android.hardware.usb.action.USB_STATE"

class MainActivity : Activity() {

    private lateinit var usbDot: TextView
    private lateinit var btDot: TextView
    private lateinit var wifiDot: TextView
    private lateinit var statusText: TextView
    private lateinit var armSwitch: Switch

    private var usbConnected = false
    private var btOn = false
    private var wifiOn = false

    private val stateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            refreshTransports()
        }
    }

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) = refreshTransports()
        override fun onLost(network: Network) = refreshTransports()
        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) = refreshTransports()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(buildUi())
        requestRuntimePermissions()

        val filter = IntentFilter().apply {
            addAction(ACTION_USB_STATE)
            addAction(BluetoothAdapter.ACTION_STATE_CHANGED)
        }
        registerReceiver(stateReceiver, filter)
        val cm = getSystemService(ConnectivityManager::class.java)
        cm?.registerDefaultNetworkCallback(networkCallback)

        if (NexLinkService.isRunning) {
            armSwitch.isChecked = true
        }
        refreshTransports()
    }

    override fun onDestroy() {
        try { unregisterReceiver(stateReceiver) } catch (_: Exception) {}
        try {
            getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(networkCallback)
        } catch (_: Exception) {}
        super.onDestroy()
    }

    // -- UI -------------------------------------------------------------------

    private fun dp(v: Int): Int = (v * resources.displayMetrics.density).toInt()

    private fun transportRow(label: String): Pair<LinearLayout, TextView> {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, dp(6), 0, dp(6))
        }
        val dot = TextView(this).apply {
            text = "●"
            textSize = 14f
            setPadding(0, 0, dp(10), 0)
        }
        val text = TextView(this).apply {
            text = label
            textSize = 16f
        }
        row.addView(dot)
        row.addView(text)
        return row to dot
    }

    private fun buildUi(): LinearLayout {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(28), dp(24), dp(24))
        }
        val title = TextView(this).apply {
            text = "NexLink"
            textSize = 26f
            setPadding(0, 0, 0, dp(4))
        }
        val subtitle = TextView(this).apply {
            text = "Share this phone's internet — VPN and all — with your PC."
            textSize = 14f
            setPadding(0, 0, 0, dp(20))
        }
        root.addView(title)
        root.addView(subtitle)

        val (usbRow, usbD) = transportRow("USB cable")
        val (btRow, btD) = transportRow("Bluetooth")
        val (wifiRow, wifiD) = transportRow("Wi-Fi")
        usbDot = usbD
        btDot = btD
        wifiDot = wifiD
        root.addView(usbRow)
        root.addView(btRow)
        root.addView(wifiRow)

        armSwitch = Switch(this).apply {
            text = "Allow PC connection"
            textSize = 18f
            setPadding(0, dp(24), 0, dp(8))
            setOnCheckedChangeListener { _, checked ->
                if (checked) {
                    startForegroundService(Intent(this@MainActivity, NexLinkService::class.java))
                } else {
                    stopService(Intent(this@MainActivity, NexLinkService::class.java))
                }
                refreshStatus()
            }
        }
        root.addView(armSwitch)

        statusText = TextView(this).apply {
            textSize = 14f
            setPadding(0, dp(8), 0, 0)
        }
        root.addView(statusText)

        val hint = TextView(this).apply {
            text = "Turn this on, then press Connect in the NexLink tray app on your PC. " +
                "Nothing connects on its own, and turning it off cuts the link instantly."
            textSize = 13f
            setPadding(0, dp(20), 0, 0)
        }
        root.addView(hint)
        return root
    }

    // -- state ------------------------------------------------------------------

    private fun requestRuntimePermissions() {
        val needed = mutableListOf<String>()
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            needed += Manifest.permission.POST_NOTIFICATIONS
        }
        if (Build.VERSION.SDK_INT >= 31 &&
            checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED
        ) {
            needed += Manifest.permission.BLUETOOTH_CONNECT
        }
        if (needed.isNotEmpty()) {
            requestPermissions(needed.toTypedArray(), 1)
        }
    }

    private fun refreshTransports() {
        // USB: the sticky USB_STATE broadcast carries the current state.
        val usbIntent = registerReceiver(null, IntentFilter(ACTION_USB_STATE))
        usbConnected = usbIntent?.getBooleanExtra("connected", false) ?: false

        btOn = try {
            getSystemService(BluetoothManager::class.java)?.adapter?.isEnabled == true
        } catch (e: SecurityException) {
            false
        }

        val cm = getSystemService(ConnectivityManager::class.java)
        val caps = cm?.activeNetwork?.let { cm.getNetworkCapabilities(it) }
        wifiOn = caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true

        runOnUiThread {
            usbDot.setTextColor(if (usbConnected) GREEN else GRAY)
            btDot.setTextColor(if (btOn) GREEN else GRAY)
            wifiDot.setTextColor(if (wifiOn) GREEN else GRAY)
            // The product rule: the switch can only be armed while a
            // transport is present. (Once on, it stays on until switched
            // off — losing a transport just makes the link unreachable.)
            armSwitch.isEnabled = anyTransport() || armSwitch.isChecked
            refreshStatus()
        }
    }

    private fun anyTransport(): Boolean = usbConnected || btOn || wifiOn

    private fun refreshStatus() {
        statusText.text = when {
            armSwitch.isChecked && anyTransport() ->
                "Armed. Press Connect on your PC."
            armSwitch.isChecked ->
                "Armed, but no transport is connected right now."
            anyTransport() ->
                "Ready. Turn on the switch when you want the PC to connect."
            else ->
                "Connect USB, Bluetooth, or Wi-Fi first — then the switch unlocks."
        }
    }

    companion object {
        private val GREEN = Color.rgb(46, 160, 67)
        private val GRAY = Color.rgb(120, 120, 120)
    }
}
