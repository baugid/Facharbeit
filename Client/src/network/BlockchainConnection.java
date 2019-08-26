package network;

import utils.ByteUtils;
import utils.ProtocolCommands;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Baut eine Verbindung zum Server auf und verwaltet diese.
 */
public class BlockchainConnection implements AutoCloseable {
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
    public BlockchainConnection(String ip, int port) throws IOException {
        s = new Socket(ip, port);
        s.setSoTimeout(10000);//10 sek timeout
        in = new DataInputStream(s.getInputStream());
        out = new DataOutputStream(s.getOutputStream());
    }

    /**
     * fragt den letzten Hash der Blockchain ab.
     *
     * @return Der letzte Hash.
     * @throws IOException sollte ein Fehler bei der Kommunikation auftreten.
     */
    public byte[] getLastHash() throws IOException {
        if (s.isClosed()) throw new IOException("Die Verbindung wurde schon beendet!");
        out.write(ProtocolCommands.LASTHASH);
        out.flush();
        switch (in.readByte()) {
            case ProtocolCommands.ERROR:
                handleServerError();
                break;
            case ProtocolCommands.HASH:
                return recieveHash();
            default:
                throw new IOException("Unerwarteter Befehl!");
        }
        return null;
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
     * Empfängt den letzten Hash der Blockchain.
     *
     * @return Der letzte Hash.
     * @throws IOException sollte ein Fehler bei der Kommunikation auftreten.
     */
    private byte[] recieveHash() throws IOException {
        return readBytes(32);
    }

    /**
     * Sendet einen Block an den Server.
     *
     * @param data Der Block.
     * @return Gibt {@code true} zurück, wenn der Block akzeptiert wurde.
     * @throws IOException sollte ein Fehler bei der Kommunikation auftreten.
     */
    public boolean sendBlock(byte[] data) throws IOException {
        if (s.isClosed()) throw new IOException("Die Verbindung wurde schon beendet!");
        out.write(ProtocolCommands.BLOCK);
        out.write(ByteUtils.toBytes(data.length));
        out.write(data);
        out.flush();
        switch (in.readByte()) {
            case ProtocolCommands.OK:
                return true;
            case ProtocolCommands.REJECT:
                return false;
            case ProtocolCommands.ERROR:
                handleServerError();
                return false;
            default:
                throw new IOException("Unerwarteter Befehl!");
        }
    }

    /**
     * Schließt die Verbindung zum Server.
     *
     * @throws IOException sollten beim Schließen irgendwelche Probleme auftreten.
     */
    @Override
    public void close() throws IOException {
        in.close();
        out.writeByte(ProtocolCommands.CLOSE);
        out.flush();
        out.close();
        s.close();
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
     * Überprüft den Status der Verbindung.
     *
     * @return Gibt {@code true} zurück, wenn die Verbindung funktionieren sollte.
     * @throws IOException sollte es irgendwelche Fehler bei der Kommunikation geben.
     */
    public boolean isValid() throws IOException {
        return !s.isClosed() && s.getInetAddress().isReachable(1000);
    }
}
