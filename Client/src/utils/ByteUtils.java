package utils;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Enthält Funktionalität zum Umgang mit Gruppen von Bytes.
 */
public class ByteUtils {
    /**
     * Buffer für Operationen mit 2 Byte Datentypen ({@code short}).
     */
    private static final ByteBuffer bufShort = ByteBuffer.allocate(2).order(ByteOrder.BIG_ENDIAN);
    /**
     * Buffer für Operationen mit 4 Byte Datentypen ({@code int}).
     */
    private static final ByteBuffer bufInt = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN);

    /**
     * Wandelt einen {@code short} in ein Bytearray um.
     *
     * @param in Der umzuwandelnde {@code short}.
     * @return Der {@code short} als Bytearray.
     */
    public static byte[] toBytes(short in) {
        bufShort.clear();
        bufShort.putShort(in);
        return bufShort.array();
    }

    /**
     * Wandelt einen {@code int} in ein Bytearray um.
     *
     * @param in Der umzuwandelnde {@code int}.
     * @return Der {@code int} als Bytearray.
     */
    public static byte[] toBytes(int in) {
        bufInt.clear();
        bufInt.putInt(in);
        return bufInt.array();
    }

    /**
     * Wandelt ein Bytearray in eine {@code Collection<Byte>} um.
     *
     * @param in Das Bytearray.
     * @return Das Bytearray als Collection.
     */
    public static Collection<Byte> toByteCollection(byte[] in) {
        ArrayList<Byte> bytes = new ArrayList<>();
        for (byte b : in) {
            bytes.add(b);
        }
        return bytes;
    }

    /**
     * Wandelt eine {@code List<Byte>} in ein Bytearray um.
     *
     * @param in Die {@code List<Byte>}.
     * @return Die {@code List<Byte>} als Bytearray.
     */
    public static byte[] toArray(List<Byte> in) {
        byte[] out = new byte[in.size()];
        for (int i = 0; i < out.length; i++) {
            out[i] = in.get(i);
        }
        return out;
    }
}
