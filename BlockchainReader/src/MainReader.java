import block.Block;
import block.Note;
import block.OwnerType;
import network.ServerConnection;
import utils.CryptoUtils;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Hauptklasse
 */
@SuppressWarnings("WeakerAccess")
public class MainReader {
    private final String[] args;
    private int keyIndex = 1;
    private OwnerType keyOwner;
    private ServerConnection connection;
    private PrivateKey keyParam;

    /**
     * Erzeugt ein neues Objekt.
     *
     * @param args Die Kommandozeilenparameter
     */
    private MainReader(String[] args) {
        this.args = args;
        if (args.length < 2) {
            sendUsageMessage();
            System.exit(1);
        }
    }

    public static void main(String[] args) {
        new MainReader(args).run();
    }

    /**
     * Gibt die Metadaten einer Liste von Blöcken aus.
     *
     * @param blocks Die Liste mit den auszugebenden Blöcken.
     */
    private void printBlocksMeta(List<Block> blocks) {
        Base64.Encoder enc = Base64.getEncoder();
        for (Block b : blocks) {
            System.out.println("Hash: " + enc.encodeToString(b.getHash()));
            System.out.println("\tJahr: " + b.getYear());
            System.out.println("\tSchulnr: " + b.getSchoolnr());
        }
    }

    /**
     * Gibt detailierte Blockinformationen aus.
     *
     * @param b Der auszugebende Block.
     */
    private void printBlock(Block b) {
        System.out.println("Jahr: " + b.getYear());
        System.out.println("Schulnr: " + b.getSchoolnr());
        System.out.println("Noten:");
        for (Note n : b.getNoten()) {
            System.out.println("\tFach: " + n.getFach() + "\tZensur: " + n.getZensur());
        }
        System.out.println("Bemerkungen: \"" + b.getBemerkungen() + "\"");
    }

    /**
     * Gibt einen evtl. angegebenen privaten Schlüssel zurück.
     *
     * @return Der private Schlüssel.
     * @see InvalidKeySpecException
     * @see NoSuchAlgorithmException
     */
    private PrivateKey getKeyPos() throws InvalidKeySpecException, NoSuchAlgorithmException {
        int possibleIndex = findParameter("-sch");
        keyOwner = OwnerType.SCHOOL;
        if (possibleIndex == -1) {
            possibleIndex = findParameter("-std");
            keyOwner = OwnerType.STUDENT;
            if (possibleIndex == -1) {
                possibleIndex = findParameter("-o");
                keyOwner = OwnerType.OTHER;
                if (possibleIndex == -1) {
                    possibleIndex = findParameter("-ez");
                    keyOwner = OwnerType.PARENT;
                    if (possibleIndex == -1) {
                        return null;
                    }
                }
                //Extract position in block
                keyIndex = Integer.parseInt(args[possibleIndex + 1]);
                ++possibleIndex;
            }
        }
        return CryptoUtils.toPrivateRSAKey(args[possibleIndex + 1]);
    }

    /**
     * Gibt eine Nachricht zur Benutzung des Programms aus.
     */
    private void sendUsageMessage() {
        System.err.println("Usage: java -jar this.jar ip:port  -S student|-h Hash [-o nr key | -std key | -sch key | -ez nr key]");
    }

    /**
     * Sucht ein Kommandzeilenparameter.
     *
     * @param param Der gesuchte Parameter.
     * @return Der Index des Parameters oder {@code -1}, sollte er nicht gefunden werden.
     */
    private int findParameter(String param) {
        for (int i = 0; i < args.length; i++) {
            if (args[i].equals(param))
                return i;
        }
        return -1;
    }

    /**
     * Stellt eine Verbindung zum angegebenen Server her.
     *
     * @return Gibt {@code true} zurück, sollte der Verbindungsversuch erfolgreich sein, anderenfalls wird {@code false} zurückgegeben.
     */
    private boolean establishConnection() {
        String[] address = args[0].split(":");
        if (address.length != 2) {
            sendUsageMessage();
            return false;
        }

        try {
            connection = new ServerConnection(address[0], Integer.parseInt(address[1]));
        } catch (IOException e) {
            System.err.println("Fehler beim Verbindungsaufbau: " + e.getLocalizedMessage());
            return false;
        }
        return true;
    }

    /**
     * Liest den evtl. vorhandenen Schlüssel ein.
     *
     * @return Gibt {@code true} zurück, sollte der Key valide sein, anderenfalls wird {@code false} zurückgegeben.
     */
    private boolean getKey() {
        try {
            keyParam = getKeyPos();
        } catch (InvalidKeySpecException e) {
            System.err.println("Der angegebene Schlüssel ist defekt!");
            return false;
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Das System scheint die benötigten kryptographischen Algorithmen nicht zu unterstützen!");
            return false;
        }
        return true;
    }

    /**
     * Empfängt den Block mit bestimmtem Hash.
     *
     * @param hash Der gewünschte Hash.
     * @return Der gewünschte Block oder {@code null}, sollte dieser nicht existieren.
     */
    private Block getBlockWithHash(byte[] hash) {
        try {
            return new Block(connection.getBlockWithHash(hash));
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Das System scheint die benötigten kryptographischen Algorithmen nicht zu unterstützen!");
            return null;
        } catch (IOException e) {
            System.err.println("Fehler beim Empfangen des Blockes: " + e.getLocalizedMessage());
            return null;
        }
    }

    /**
     * Parsed den verschlüsselten Teil eines Blockes.
     *
     * @param b Der zu parsende Block.
     * @return Gibt {@code true} zurück, wenn es kein Fehler gab.
     */
    private boolean parseBlock(Block b) {
        try {
            b.parseEncrypted(keyParam, keyIndex, keyOwner);
        } catch (InvalidKeyException e) {
            System.err.println("Entweder ist der angegebene oder der sich im Block befindende Schlüssel fehlerhaft!");
            return false;
        } catch (GeneralSecurityException e) {
            System.err.println("Das System scheint die benötigten kryptographischen Algorithmen nicht zu unterstützen!");
            return false;
        } catch (UnsupportedEncodingException e) {
            System.err.println("Das System unterstützt keine UTF-8 Kodierung");
            return false;
        }
        return true;
    }

    /**
     * Überprüft die Noten des Blockes.
     *
     * @param b Der zu überprüfende Block.
     * @return Gibt {@code true} zurück, wenn der Block valide ist.
     */
    private boolean verifyBlock(Block b) {
        try {
            if (!b.verifyGrades()) {
                System.err.println("Manche Noten scheinen fehlerhaft zu sein!");
            }
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Das System scheint die benötigten kryptographischen Algorithmen nicht zu unterstützen!");
            return false;
        }
        return true;
    }

    /**
     * Konvertiert einen String zu einem öffentlichen RSAkey.
     *
     * @param key Der Key als String.
     * @return Der Key.
     */
    private PublicKey castKey(String key) {
        try {
            return CryptoUtils.toPublicRSAKey(key);
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Das System scheint die benötigten kryptographischen Algorithmen nicht zu unterstützen!");
            return null;
        } catch (InvalidKeySpecException e) {
            System.err.println("Der angegebene Schlüssel ist defekt!");
            return null;
        }
    }

    /**
     * Führt das gesamte Programm aus.
     */
    private void run() {
        if (!getKey()) return;
        int parameterPos = findParameter("-h");
        if (parameterPos != -1) {
            //load block via hash
            if (keyParam == null || parameterPos + 1 == args.length) {
                sendUsageMessage();
                return;
            }
            Base64.Decoder dec = Base64.getDecoder();
            byte[] hash = dec.decode(args[parameterPos + 1]);
            if (!establishConnection()) return;
            Block b = getBlockWithHash(hash);
            if (b == null) {
                connection.close();
                return;
            }
            if (!parseBlock(b)) {
                connection.close();
                return;
            }
            if (!verifyBlock(b)) {
                connection.close();
                return;
            }
            printBlock(b);
        } else {
            //load block via student
            parameterPos = findParameter("-S");
            if (parameterPos != -1) {
                PublicKey k = castKey(args[parameterPos + 1]);
                if (!establishConnection()) return;
                List<byte[]> blockDataList = loadBlocks(k);
                if (blockDataList == null) {
                    connection.close();
                    return;
                }
                List<Block> blocks = new ArrayList<>();
                for (byte[] blockData : blockDataList) {
                    try {
                        blocks.add(new Block(blockData));
                    } catch (NoSuchAlgorithmException e) {
                        System.err.println("Das System scheint die benötigten kryptographischen Algorithmen nicht zu unterstützen!");
                        connection.close();
                        return;

                    }
                }
                printBlocksMeta(blocks);
            } else {
                sendUsageMessage();
            }
        }
        connection.close();
    }

    /**
     * Läd die Blöcke von einem Schüler.
     *
     * @param k Der Schüler.
     * @return Eine Liste mit sämtlichen zum Schüler gehörigen Blöcken.
     */
    private List<byte[]> loadBlocks(PublicKey k) {
        try {
            return connection.getBlocksFromStudent(k);
        } catch (IOException e) {
            System.err.println("Fehler beim Empfangen der Blöcke: " + e.getLocalizedMessage());
            return null;
        } catch (InvalidKeySpecException e) {
            System.err.println("Der angegebenen Schlüssel ist defekt!");
            return null;
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Das System scheint die benötigten kryptographischen Algorithmen nicht zu unterstützen!");
            return null;
        }
    }
}
