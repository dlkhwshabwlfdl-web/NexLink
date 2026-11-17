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
import java.util.concurrent.atomic.AtomicBoolean

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

    private sealed class Flow {
        class Tcp(val socket: Socket) : Flow()
        class Udp(val socket: DatagramSocket, val alive: AtomicBoolean) : Flow()
        object Dns : Flow()
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
                    flows[frame.flow] = Flow.Dns
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
            flows[flow] = Flow.Udp(socket, alive)
            send(Protocol.Frame.OpenOk(flow))
            Thread {
                val buf = ByteArray(64 * 1024)
                socket.soTimeout = 1000
                while (alive.get() && running.get()) {
                    try {
                        val packet = DatagramPacket(buf, buf.size)
                        socket.receive(packet)
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
                } catch (_: Exception) {
                    // UDP is lossy by nature; a failed send drops the datagram.
                }
            }
            Flow.Dns -> {
                val query = frame.data
                Thread {
                    val answer = dnsResolver(query)
                    if (answer != null) {
                        send(Protocol.Frame.Data(frame.flow, answer))
                    }
                    // No answer -> stay silent; the PC's resolver times out
                    // and retries, exactly like a lost UDP response.
                }.start()
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
            Flow.Dns -> {}
        }
    }

    private fun closeQuietly(flow: Flow) {
        when (flow) {
            is Flow.Tcp -> try { flow.socket.close() } catch (_: Exception) {}
            is Flow.Udp -> {
                flow.alive.set(false)
                try { flow.socket.close() } catch (_: Exception) {}
            }
            Flow.Dns -> {}
        }
    }
}
