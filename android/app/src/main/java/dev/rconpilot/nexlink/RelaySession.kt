package dev.rconpilot.nexlink

import android.util.Log
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * One PC<->phone link session: reads NXLP frames and relays flows with
 * ordinary Android sockets — the exact semantics of the `simphone` test
 * double on the PC side, which is what the end-to-end test verifies.
 *
 * Because every flow is re-originated by a socket owned by this app, the
 * traffic follows the phone's own routing: the active VPN, its DNS, all of
 * it. Nothing here uses VpnService, so it never fights the phone's VPN app
 * for the single VPN slot.
 *
 * @param dnsResolver resolves one raw DNS query with the phone's resolver
 *                    and returns the raw response, or null on failure.
 * @param armed       whether the phone's arm switch is currently on.
 */
class RelaySession(
    private val input: InputStream,
    private val output: OutputStream,
    private val dnsResolver: (ByteArray) -> ByteArray?,
    private val armed: () -> Boolean,
    private val phoneName: String,
    private val onFinished: () -> Unit,
) {
    private val tag = "NexLinkSession"
    private val writeLock = Any()
    private val flows = ConcurrentHashMap<Long, Flow>()
    private val running = AtomicBoolean(true)

    // DNS answers come from a small fixed pool instead of one thread per
    // query: a burst of lookups used to spawn unbounded threads.
    private val dnsPool: ExecutorService = Executors.newFixedThreadPool(DNS_POOL_SIZE) { r ->
        Thread(r, "NexLink-dns").apply { isDaemon = true }
    }

    companion object {
        private const val DNS_POOL_SIZE = 4
        // A UDP (or DNS) flow with no traffic in either direction for this
        // long is closed by the phone, even if the PC never sends Close —
        // otherwise a silent PC leaks a DatagramSocket per flow forever.
        // The PC engine expires its own side after 60 s; 90 s here means
        // the phone only steps in when the PC side did not (link stalled,
        // PC crashed without Bye, ...).
        private const val UDP_IDLE_TIMEOUT_MS = 90_000L
        private const val IDLE_SWEEP_INTERVAL_MS = 10_000L
    }

    private sealed class Flow {
        class Tcp(val socket: Socket) : Flow()
        class Udp(
            val socket: DatagramSocket,
            val alive: AtomicBoolean,
            val lastActivity: AtomicLong = AtomicLong(System.currentTimeMillis()),
        ) : Flow()
        // Stateless marker: one DNS flow lives per PC resolver flow id and
        // only carries queries/answers, so it gets the same idle sweep.
        class Dns(val lastActivity: AtomicLong = AtomicLong(System.currentTimeMillis())) : Flow()
    }

    private fun send(frame: Protocol.Frame) {
        val bytes = Protocol.encode(frame)
        synchronized(writeLock) {
            try {
                output.write(bytes)
                output.flush()
            } catch (e: Exception) {
                // Link is gone; the read loop will notice and end the session.
            }
        }
    }

    fun run() {
        startIdleSweep()
        try {
            val reader = Protocol.Reader(input)
            while (running.get()) {
                val frame = reader.next() ?: break
                when (frame) {
                    is Protocol.Frame.Hello ->
                        send(Protocol.Frame.HelloAck(armed(), phoneName))
                    is Protocol.Frame.Open -> openFlow(frame)
                    is Protocol.Frame.Data -> onData(frame)
                    is Protocol.Frame.Close -> closeFlow(frame.flow, frame.flags)
                    Protocol.Frame.Ping -> send(Protocol.Frame.Pong)
                    Protocol.Frame.Pong -> {}
                    Protocol.Frame.Bye -> break
                    is Protocol.Frame.HelloAck, is Protocol.Frame.OpenOk, is Protocol.Frame.OpenErr -> {}
                }
            }
        } catch (e: Exception) {
            Log.i(tag, "session ended: ${e.message}")
        } finally {
            running.set(false)
            dnsPool.shutdownNow()
            flows.values.forEach { closeQuietly(it) }
            flows.clear()
            try { input.close() } catch (_: Exception) {}
            try { output.close() } catch (_: Exception) {}
            onFinished()
        }
    }

    private fun openFlow(frame: Protocol.Frame.Open) {
        if (!armed()) {
            send(Protocol.Frame.OpenErr(frame.flow, Protocol.ERR_NOT_ARMED))
            return
        }
        val dest = InetAddress.getByAddress(frame.ip)
        when (frame.proto) {
            Protocol.PROTO_TCP -> openTcp(frame.flow, dest, frame.port)
            Protocol.PROTO_UDP -> {
                if (frame.port == 53) {
                    // DNS interception: the phone resolves, the dialed
                    // address is ignored on purpose (see ARCHITECTURE.md).
                    flows[frame.flow] = Flow.Dns()
                    send(Protocol.Frame.OpenOk(frame.flow))
                } else {
                    openUdp(frame.flow, dest, frame.port)
                }
            }
            else -> send(Protocol.Frame.OpenErr(frame.flow, Protocol.ERR_CONNECT_FAILED))
        }
    }

    private fun openTcp(flow: Long, dest: InetAddress, port: Int) {
        Thread {
            try {
                val socket = Socket()
                socket.connect(InetSocketAddress(dest, port), 10_000)
                socket.tcpNoDelay = true
                flows[flow] = Flow.Tcp(socket)
                send(Protocol.Frame.OpenOk(flow))
                val buf = ByteArray(16 * 1024)
                try {
                    while (running.get()) {
                        val n = socket.getInputStream().read(buf)
                        if (n < 0) {
                            flows.remove(flow)
                            send(Protocol.Frame.Close(flow, Protocol.CLOSE_FIN))
                            return@Thread
                        }
                        if (n > 0) {
                            send(Protocol.Frame.Data(flow, buf.copyOf(n)))
                        }
                    }
                } catch (e: Exception) {
                    flows.remove(flow)
                    send(Protocol.Frame.Close(flow, Protocol.CLOSE_RST))
                }
            } catch (e: Exception) {
                send(Protocol.Frame.OpenErr(flow, Protocol.ERR_CONNECT_FAILED))
            }
        }.start()
    }

    private fun openUdp(flow: Long, dest: InetAddress, port: Int) {
        try {
            val socket = DatagramSocket()
            socket.connect(dest, port)
            val alive = AtomicBoolean(true)
            val udpFlow = Flow.Udp(socket, alive)
            flows[flow] = udpFlow
            send(Protocol.Frame.OpenOk(flow))
            Thread {
                val buf = ByteArray(64 * 1024)
                socket.soTimeout = 1000
                while (alive.get() && running.get()) {
                    try {
                        val packet = DatagramPacket(buf, buf.size)
                        socket.receive(packet)
                        udpFlow.lastActivity.set(System.currentTimeMillis())
                        send(Protocol.Frame.Data(flow, buf.copyOf(packet.length)))
                    } catch (e: java.net.SocketTimeoutException) {
                        // idle tick; loop re-checks the alive flag
                    } catch (e: Exception) {
                        return@Thread
                    }
                }
            }.start()
        } catch (e: Exception) {
            send(Protocol.Frame.OpenErr(flow, Protocol.ERR_CONNECT_FAILED))
        }
    }

    /**
     * Closes UDP/DNS flows that saw no traffic in either direction for
     * [UDP_IDLE_TIMEOUT_MS]. Runs on a daemon thread started by [run];
     * closing the phone socket frees it even when the PC never sends
     * Close, and the Close FIN tells the PC side the flow is gone.
     */
    private fun startIdleSweep() {
        Thread({
            while (running.get()) {
                try {
                    Thread.sleep(IDLE_SWEEP_INTERVAL_MS)
                } catch (_: InterruptedException) {
                    return
                }
                sweepIdleFlows()
            }
        }, "NexLink-udp-sweep").apply { isDaemon = true; start() }
    }

    private fun sweepIdleFlows() {
        val now = System.currentTimeMillis()
        val idle = flows.entries
            .filter { (_, f) ->
                val last = when (f) {
                    is Flow.Udp -> f.lastActivity.get()
                    is Flow.Dns -> f.lastActivity.get()
                    is Flow.Tcp -> null
                } ?: return@filter false
                now - last > UDP_IDLE_TIMEOUT_MS
            }
            .map { it.key }
        for (flow in idle) {
            val removed = flows.remove(flow) ?: continue
            closeQuietly(removed)
            send(Protocol.Frame.Close(flow, Protocol.CLOSE_FIN))
            Log.i(tag, "closed idle udp flow $flow")
        }
    }

    private fun onData(frame: Protocol.Frame.Data) {
        when (val flow = flows[frame.flow]) {
            is Flow.Tcp -> {
                try {
                    val out = flow.socket.getOutputStream()
                    out.write(frame.data)
                    out.flush()
                } catch (e: Exception) {
                    flows.remove(frame.flow)
                    send(Protocol.Frame.Close(frame.flow, Protocol.CLOSE_RST))
                }
            }
            is Flow.Udp -> {
                try {
                    flow.socket.send(DatagramPacket(frame.data, frame.data.size))
                    flow.lastActivity.set(System.currentTimeMillis())
                } catch (_: Exception) {
                    // UDP is lossy by nature; a failed send drops the datagram.
                }
            }
            is Flow.Dns -> {
                val query = frame.data
                flow.lastActivity.set(System.currentTimeMillis())
                dnsPool.execute {
                    val answer = dnsResolver(query)
                    if (answer != null) {
                        flow.lastActivity.set(System.currentTimeMillis())
                        send(Protocol.Frame.Data(frame.flow, answer))
                    }
                    // No answer -> stay silent; the PC's resolver times out
                    // and retries, exactly like a lost UDP response.
                }
            }
            null -> {}
        }
    }

    private fun closeFlow(flow: Long, flags: Int) {
        val f = flows.remove(flow) ?: return
        when (f) {
            is Flow.Tcp -> try {
                if (flags and Protocol.CLOSE_RST != 0) f.socket.close()
                else f.socket.shutdownOutput()
            } catch (_: Exception) {}
            is Flow.Udp -> {
                f.alive.set(false)
                try { f.socket.close() } catch (_: Exception) {}
            }
            is Flow.Dns -> {}
        }
    }

    private fun closeQuietly(flow: Flow) {
        when (flow) {
            is Flow.Tcp -> try { flow.socket.close() } catch (_: Exception) {}
            is Flow.Udp -> {
                flow.alive.set(false)
                try { flow.socket.close() } catch (_: Exception) {}
            }
            is Flow.Dns -> {}
        }
    }
}
