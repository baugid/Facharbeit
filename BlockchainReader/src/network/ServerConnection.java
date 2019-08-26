package network;

import utils.ByteUtils;
import utils.CryptoUtils;
import utils.ProtocolCommands;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

/**
 * Stellt die Verbindung zum Server her und verwaltet diese.
 */
public class ServerConnection implements AutoCloseable {
    /**
     * Der Socket, der mit dem Server verbunden ist.
     */
    private Socket s;
    /**
     * Der InputStream vom Socket.
     */
    private DataInputStream in;
    /**
     * Der OutputStream vom Socket.
     */
    private DataOutputStream out;

    /**
     * Stellt die Verbindung zum Server her.
     *
     * @param ip   Die IP des Servers.
     * @param port Der Port auf dem Server.
     * @throws IOException sollte ein Fehler beim Verbinden auftreten.
     */
    public ServerConnection(String ip, int port) throws IOException {
        s = new Socket(ip, port);
        s.setSoTimeout(10000);
        in = new DataInputStream(s.getInputStream());
        out = new DataOutputStream(s.getOutputStream());
    }

    /**
     * Fragt den Block mit einem bestimmten Hash an.
     *
     * @param hash Der Hash des Blockes.
     * @return Die Byterepräsention des Blockes.
     * @throws IOException              sollte es irgendwelche Fehler bei der Kommunikation geben.
     * @throws IllegalArgumentException sollte der Hash nicht 256 Bit lang sein.
     */
    public byte[] getBlockWithHash(byte[] hash) throws IOException, IllegalArgumentException {
        if (hash.length != 32) throw new IllegalArgumentException("Der Hash muss 32 Byte lang sein!");
        out.write(ProtocolCommands.GETBLOCK);
        out.write(hash);
        out.flush();
        switch (in.readByte()) {
            case ProtocolCommands.ERROR:
                handleServerError();
                break;
            case ProtocolCommands.BLOCK:
                return receiveBlock();
            default:
                throw new IOException("Unerwarteter Befehl!");
        }
        return null;
    }

    /**
     * Empfängt den Block.
     *
     * @return Die Byterepräsention des Blockes.
     * @throws IOException sollte es irgendwelche Fehler bei der Kommunikation geben.
     */
    private byte[] receiveBlock() throws IOException {
        byte[] data = readBytes(4);
        int size = ByteUtils.toInt(data);
        return readBytes(size);
    }

    /**
     * Empfängt alle Blöcke von einem Schüler.
     *
     * @param key Der Schüler.
     * @return Alle mit diesem Schüler verbundene Blöcke.
     * @throws IOException              sollte es irgendwelche Fehler bei der Kommunikation geben.
     * @throws InvalidKeySpecException  sollte der übergebene Key fehlerhaft sein.
     * @throws NoSuchAlgorithmException sollte ein benötigter Algorithmus nicht gefunden werden.
     */
    public List<byte[]> getBlocksFromStudent(PublicKey key) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        out.write(ProtocolCommands.SGETBLOCK);
        byte[] keyData = CryptoUtils.encodeRSAKey(key);
        out.write(ByteUtils.toBytes(keyData.length));
        out.write(keyData);
        out.flush();
        ArrayList<byte[]> blocks = new ArrayList<>();
        getBlocksLoop:
        while (true)
            switch (in.readByte()) {
                case ProtocolCommands.BLOCK:
                    blocks.add(receiveBlock());
                    break;
                case ProtocolCommands.CLOSE:
                default:
                    break getBlocksLoop;
            }
        return blocks;
    }

    /**
     * Empfängt den vom Server gesendeten Fehler ein.
     *
     * @throws IOException Der Fehler als Exception.
     */
    private void handleServerError() throws IOException {
        byte[] data = readBytes(4);
        int size = ByteUtils.toInt(data);
        throw new IOException("Fehlerbericht vom Server: " + new String(readBytes(size), StandardCharsets.UTF_8));
    }

    /**
     * Empfängt {@code amount} Bytes vom Server.
     *
     * @param amount Die Anzahl zu empfangender Bytes.
     * @return Die empfangenen Bytes.
     * @throws IOException sollte es irgendwelche Fehler bei der Kommunikation geben.
     */
    private byte[] readBytes(int amount) throws IOException {
        int count = 0;
        byte[] data = new byte[amount];
        do {
            int readThisTime = in.read(data, count, amount - count);
            if (readThisTime == -1)
                throw new IOException("Unerwartetes Ende der Übertragung!");
            count += readThisTime;
        } while (!s.isClosed() && count < amount);
        return data;
    }

    /**
     * Schließt die Verbindung.
     */
    @Override
    public void close() {
        try {
            out.writeByte(ProtocolCommands.CLOSE);
            out.flush();
            out.close();
            s.close();
            in.close();
        } catch (IOException ignored) {
        }
    }
}
