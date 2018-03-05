package network;

import data.Block;
import data.Blockchain;
import utils.ByteUtils;
import utils.CryptoUtils;
import utils.ProtocolCommands;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.List;
import java.util.function.Consumer;

/**
 * Repräsentiert die Verbindung zu einem Client.
 */
class Client implements AutoCloseable {
    /**
     * Die Blockchain.
     */
    private final Blockchain chain;
    /**
     * Der Socket zum Client.
     */
    private final Socket s;
    /**
     * Methode die mit {@code this} aufgerufen wird, sollte die Verbindung geschlossen werden.
     */
    private final Consumer<Client> onExit;
    /**
     * Der InputStream vom Socket.
     */
    private DataInputStream in;
    /**
     * Der OutputStream vom Socket.
     */
    private DataOutputStream out;
    /**
     * Die nächste auszuführende Aufgabe.
     */
    private Runnable nextTask = null;
    /**
     * Anzahl der Male, die der Client keine erwarteten Daten gesendet hat.
     * Sollte dieser Counter zu hoch werden, wird die Verbindung gekappt.
     */
    private int requeueCounter = 0;
    /**
     * Anzahl der gelesenen Bytes.
     */
    private int readCount = 0;
    /**
     * Array, in das die empfangenen Daten eingelesen werden.
     */
    private byte[] readData;

    /**
     * Erzeugt ein neues Objekt.
     *
     * @param s      Der Socket zum Client.
     * @param chain  Die Blockchain.
     * @param onExit Die Methode, die beim Schließen aufgerufen werden soll.
     * @throws IOException sollte es Probleme beim Verbindungsaufbau geben.
     */
    Client(Socket s, Blockchain chain, Consumer<Client> onExit) throws IOException {
        this.s = s;
        this.chain = chain;
        this.onExit = onExit;
        out = new DataOutputStream(s.getOutputStream());
        in = new DataInputStream(s.getInputStream());
    }

    /**
     * Verarbeitet etwaige Fehler.
     *
     * @param e Der entstandene Fehler.
     */
    private void handleException(Exception e) {
        System.err.println("Fehler mit Client: " + e.getLocalizedMessage());
        secureClose();
    }

    /**
     * Regelmäßig aufgerufene Methode, die neue Befehle abfragt bzw. die Aufgaben delegiert
     */
    public void handle() {
        if (s.isClosed() || !s.isConnected())
            secureClose();
        if (nextTask != null) {
            nextTask.run();
        } else {
            try {
                if (in.available() != 0) {
                    byte type = in.readByte();
                    switch (type) {
                        case ProtocolCommands.LASTHASH:
                            nextTask = this::sendLastHash;
                            break;
                        case ProtocolCommands.ERROR:
                            nextTask = () -> sendErrorMsg("Wrong usage of the Error command!");
                            break;
                        case ProtocolCommands.BLOCK:
                            requeueCounter = 0;
                            readCount = 0;
                            readData = new byte[4];
                            nextTask = this::receiveNewBlock;
                            break;
                        case ProtocolCommands.CLOSE:
                            nextTask = this::secureClose;
                            break;
                        case ProtocolCommands.HASH:
                            nextTask = () -> sendErrorMsg("Wrong usage of the Hash command!");
                            break;
                        case ProtocolCommands.OK:
                            nextTask = () -> sendErrorMsg("Wrong usage of the OK command!");
                            break;
                        case ProtocolCommands.REJECT:
                            nextTask = () -> sendErrorMsg("Wrong usage of the Reject command!");
                            break;
                        case ProtocolCommands.GETBLOCK:
                            requeueCounter = 0;
                            readCount = 0;
                            readData = new byte[32];
                            nextTask = this::receiveBlockHash;
                            break;
                        case ProtocolCommands.SGETBLOCK:
                            requeueCounter = 0;
                            readCount = 0;
                            readData = new byte[4];
                            nextTask = this::receiveStudentLen;
                            break;
                        default:
                            nextTask = () -> sendErrorMsg("Unknown command!");
                    }
                }
            } catch (IOException e) {
                handleException(e);
            }
        }
    }

    /**
     * Empfängt die Länge des Schlüssels des Schülers und sorgt für das Abfragen dieses.
     */
    private void receiveStudentLen() {
        readBytes(() -> {
            readCount = 0;
            requeueCounter = 0;
            readData = new byte[ByteUtils.toInt(readData)];
            nextTask = this::receiveStudent;
        });
    }

    /**
     * Empfängt den Schlüssel des Schülers und sorgt für das Senden der Blöcke.
     */
    private void receiveStudent() {
        //ReadBytes and then set nextTask to the code
        readBytes(() -> nextTask = () -> {
            try {
                sendStudentBlock(CryptoUtils.toPublicRSAKey(readData));
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                nextTask = () -> sendErrorMsg("Illegal key!");
                secureClose();
            }
        });
    }

    /**
     * Sendet alle Blöcke eines Schülers.
     *
     * @param student Der Schüler.
     */
    private void sendStudentBlock(PublicKey student) {
        sendAllBlocks(chain.getStudentBlocks(student));
    }

    /**
     * Sendet die spezifizierten Blöcke.
     *
     * @param blocks Die Blöcke, die gesendet werden sollen.
     */
    private void sendAllBlocks(List<Block> blocks) {
        if (blocks.size() == 0) {
            try {
                out.write(ProtocolCommands.CLOSE);
                secureClose();
            } catch (IOException e) {
                handleException(e);
            }
            nextTask = null;
            return;
        }
        Block current = blocks.get(0);
        byte[] currentData = current.getData();
        try {
            out.write(ProtocolCommands.BLOCK);
            out.write(ByteUtils.toBytes(currentData.length));
            out.write(currentData);
            if (blocks.size() > 1)
                nextTask = () -> sendAllBlocks(blocks.subList(1, blocks.size()));
            else {
                out.write(ProtocolCommands.CLOSE);
                secureClose();
            }
        } catch (IOException e) {
            handleException(e);
        }
    }

    /**
     * Empfängt den Hash des gewünschten Blockes und sendet diesen im nächsten Zyklus.
     */
    private void receiveBlockHash() {
        //readBytes and set nextTask to sendHashBlock
        readBytes(() -> nextTask = () -> sendHashBlock(readData));
    }

    /**
     * Sendet den Block mit passendem Hash.
     *
     * @param hash Der gewünschte Blockhash.
     */
    private void sendHashBlock(byte[] hash) {
        Block b = chain.getBlock(hash);
        if (b == null) {
            nextTask = () -> sendErrorMsg("Block does not exist!");
            return;
        }
        byte[] blockData = b.getData();
        try {
            out.write(ProtocolCommands.BLOCK);
            out.write(ByteUtils.toBytes(blockData.length));
            out.write(blockData);
        } catch (IOException e) {
            handleException(e);
        }
        nextTask = null;
    }

    /**
     * Empfängt die Größe eines neuen Blocks und im nächsten Zyklus diesen Block.
     */
    private void receiveNewBlock() {
        readBytes(() -> {
            readCount = 0;
            requeueCounter = 0;
            readData = new byte[ByteUtils.toInt(readData)];
            nextTask = this::receiveBlock;
        });
    }

    /**
     * Empfängt und verifiziert einen neuen Block.
     */
    private void receiveBlock() {
        readBytes(() -> {
            try {
                if (chain.verifyAndAdd(readData)) {
                    out.write(ProtocolCommands.OK);
                } else {
                    out.write(ProtocolCommands.REJECT);
                }
                nextTask = null;
            } catch (IOException e) {
                handleException(e);
            }
        });
    }

    /**
     * Schließt die Verbindung. Dabei werden sämtliche Exceptions einfach ignoriert.
     */
    private void secureClose() {
        try {
            this.close();
        } catch (Exception ignored) {
        }
    }

    /**
     * Sendet den Hash des letzten Blockes in der Chain.
     */
    private void sendLastHash() {
        try {
            out.write(ProtocolCommands.HASH);
            out.write(chain.getLastHash());
        } catch (IOException e) {
            secureClose();
        }
        nextTask = null;
    }

    /**
     * Sendet eine Fehlermeldung an den Client.
     *
     * @param msg Die gewünschte Fehlermeldung.
     */
    private void sendErrorMsg(String msg) {
        byte[] data = new byte[0];
        try {
            data = msg.getBytes("UTF-8");
        } catch (UnsupportedEncodingException ignored) {
            //shouldn't occur
            secureClose();
        }
        try {
            out.write(ProtocolCommands.ERROR);
            out.write(ByteUtils.toBytes(data.length));
            out.write(data);
            secureClose();
        } catch (IOException e) {
            handleException(e);
        }
    }

    @Override
    public void close() throws Exception {
        nextTask = null;
        in.close();
        out.close();
        s.close();
        onExit.accept(this);
    }

    /**
     * Liest eine gewisse Anzahl an Bytes ein (soviele wie in {@code readData} passen).
     *
     * @param andThen Die Aufgabe, die ausgeführt wird, wenn die Bytes gelesen wurden.
     */
    private void readBytes(Runnable andThen) {
        if (requeueCounter == 10)
            secureClose();
        try {
            if (in.available() == 0) {
                requeueCounter++;
                nextTask = () -> readBytes(andThen);
                return;
            }

            do {
                int readThisTime = in.read(readData, readCount, readData.length - readCount);
                if (readThisTime == -1)
                    throw new IOException("Unexpected end of stream!");
                readCount += readThisTime;
            } while (!s.isClosed() && readCount < readData.length);
            andThen.run();
        } catch (IOException e) {
            handleException(e);
        }
    }
}