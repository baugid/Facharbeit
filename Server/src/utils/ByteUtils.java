package utils;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

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
     * Wandelt ein Bytearray in einen {@code int} um.
     *
     * @param in Das umzuwandelnde Bytearray.
     * @return Der daraus resultierende {@code int}.
     */
    public static int toInt(byte[] in) {
        bufInt.clear();
        bufInt.put(in);
        bufInt.position(0);
        return bufInt.getInt();
    }

    /**
     * Wandelt ein Bytearray in einen {@code short} um.
     *
     * @param in Das umzuwandelnde Bytearray.
     * @return Der daraus resultierende {@code short}.
     */
    public static short toShort(byte[] in) {
        bufShort.clear();
        bufShort.put(in);
        bufShort.position(0);
        return bufShort.getShort();
    }

}
