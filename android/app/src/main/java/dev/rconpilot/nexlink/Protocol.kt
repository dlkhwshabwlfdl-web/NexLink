package dev.rconpilot.nexlink

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream

/**
 * NXLP v1 — the NexLink wire protocol. This is the Kotlin mirror of
 * `pc/crates/nxcore/src/proto.rs`; the two must stay in sync.
 *
 * Frame layout: `u32 BE body_len | u8 type | payload…`
 * where `body_len` counts the type byte plus the payload.
 */
object Protocol {
    const val VERSION = 1
    const val PORT = 47777

    const val T_HELLO = 0x01
    const val T_HELLO_ACK = 0x02
    const val T_OPEN = 0x03
    const val T_OPEN_OK = 0x04
    const val T_OPEN_ERR = 0x05
    const val T_DATA = 0x06
    const val T_CLOSE = 0x07
    const val T_PING = 0x08
    const val T_PONG = 0x09
    const val T_BYE = 0x0A

    const val PROTO_TCP = 6
    const val PROTO_UDP = 17

    const val CLOSE_FIN = 0x01
    const val CLOSE_RST = 0x02

    const val ERR_NOT_ARMED = 1
    const val ERR_CONNECT_FAILED = 2

    sealed class Frame {
        data class Hello(val version: Int, val name: String) : Frame()
        data class HelloAck(val armed: Boolean, val name: String) : Frame()
        data class Open(val flow: Long, val proto: Int, val ip: ByteArray, val port: Int) : Frame()
        data class OpenOk(val flow: Long) : Frame()
        data class OpenErr(val flow: Long, val code: Int) : Frame()
        data class Data(val flow: Long, val data: ByteArray) : Frame()
        data class Close(val flow: Long, val flags: Int) : Frame()
        object Ping : Frame()
        object Pong : Frame()
        object Bye : Frame()
    }

    fun encode(frame: Frame): ByteArray {
        val body = ByteArrayOutputStream()
        fun u32(v: Long) {
            body.write((v ushr 24).toInt())
            body.write((v ushr 16).toInt())
            body.write((v ushr 8).toInt())
            body.write(v.toInt())
        }
        fun u16(v: Int) {
            body.write(v ushr 8)
            body.write(v)
        }
        when (frame) {
            is Frame.Hello -> {
                body.write(T_HELLO)
                u16(frame.version)
                body.write(frame.name.toByteArray(Charsets.UTF_8))
            }
            is Frame.HelloAck -> {
                body.write(T_HELLO_ACK)
                body.write(if (frame.armed) 1 else 0)
                body.write(frame.name.toByteArray(Charsets.UTF_8))
            }
            is Frame.Open -> {
                body.write(T_OPEN)
                u32(frame.flow)
                body.write(frame.proto)
                body.write(frame.ip)
                u16(frame.port)
            }
            is Frame.OpenOk -> {
                body.write(T_OPEN_OK)
                u32(frame.flow)
            }
            is Frame.OpenErr -> {
                body.write(T_OPEN_ERR)
                u32(frame.flow)
                body.write(frame.code)
            }
            is Frame.Data -> {
                body.write(T_DATA)
                u32(frame.flow)
                body.write(frame.data)
            }
            is Frame.Close -> {
                body.write(T_CLOSE)
                u32(frame.flow)
                body.write(frame.flags)
            }
            Frame.Ping -> body.write(T_PING)
            Frame.Pong -> body.write(T_PONG)
            Frame.Bye -> body.write(T_BYE)
        }
        val bodyBytes = body.toByteArray()
        val out = ByteArrayOutputStream(bodyBytes.size + 4)
        out.write(bodyBytes.size ushr 24)
        out.write(bodyBytes.size ushr 16)
        out.write(bodyBytes.size ushr 8)
        out.write(bodyBytes.size)
        out.write(bodyBytes)
        return out.toByteArray()
    }

    /** Incremental frame reader over a blocking stream. */
    class Reader(private val input: InputStream) {
        private var buf = ByteArray(0)

        /** Returns the next frame, or null on clean EOF. */
        fun next(): Frame? {
            while (true) {
                if (buf.size >= 4) {
                    val len = ((buf[0].toInt() and 0xFF) shl 24) or
                        ((buf[1].toInt() and 0xFF) shl 16) or
                        ((buf[2].toInt() and 0xFF) shl 8) or
                        (buf[3].toInt() and 0xFF)
                    if (len <= 0 || len > 16 * 1024 * 1024) {
                        throw IOException("NXLP frame length out of range: $len")
                    }
                    if (buf.size >= 4 + len) {
                        val body = buf.copyOfRange(4, 4 + len)
                        buf = buf.copyOfRange(4 + len, buf.size)
                        return decode(body)
                    }
                }
                val chunk = ByteArray(64 * 1024)
                val n = input.read(chunk)
                if (n < 0) return null
                if (n == 0) continue
                val merged = ByteArray(buf.size + n)
                System.arraycopy(buf, 0, merged, 0, buf.size)
                System.arraycopy(chunk, 0, merged, buf.size, n)
                buf = merged
            }
        }

        private fun decode(body: ByteArray): Frame {
            if (body.isEmpty()) throw IOException("empty NXLP frame")
            val p = body.copyOfRange(1, body.size)
            fun u32At(i: Int): Long =
                ((p[i].toLong() and 0xFF) shl 24) or ((p[i + 1].toLong() and 0xFF) shl 16) or
                    ((p[i + 2].toLong() and 0xFF) shl 8) or (p[i + 3].toLong() and 0xFF)
            fun u16At(i: Int): Int =
                ((p[i].toInt() and 0xFF) shl 8) or (p[i + 1].toInt() and 0xFF)
            return when (body[0].toInt()) {
                T_HELLO -> Frame.Hello(u16At(0), String(p, 2, p.size - 2, Charsets.UTF_8))
                T_HELLO_ACK -> Frame.HelloAck(
                    p.isNotEmpty() && p[0].toInt() == 1,
                    if (p.size > 1) String(p, 1, p.size - 1, Charsets.UTF_8) else ""
                )
                T_OPEN -> Frame.Open(u32At(0), p[4].toInt(), p.copyOfRange(5, 9), u16At(9))
                T_OPEN_OK -> Frame.OpenOk(u32At(0))
                T_OPEN_ERR -> Frame.OpenErr(u32At(0), p[4].toInt())
                T_DATA -> Frame.Data(u32At(0), p.copyOfRange(4, p.size))
                T_CLOSE -> Frame.Close(u32At(0), p[4].toInt())
                T_PING -> Frame.Ping
                T_PONG -> Frame.Pong
                T_BYE -> Frame.Bye
                else -> throw IOException("unknown NXLP frame type ${body[0]}")
            }
        }
    }
}
