package utils;

/**
 * Listet sämtliche verfügbaren Befehle des Übertragungsprotokolls auf.
 */
public class ProtocolCommands {
    public static final byte LASTHASH = 27;
    public static final byte GETBLOCK = 42;
    public static final byte SGETBLOCK = 48;
    public static final byte BLOCK = 50;
    public static final byte OK = 30;
    public static final byte REJECT = 57;
    public static final byte CLOSE = 15;
    public static final byte ERROR = 13;
    public static final byte HASH = 18;
}
