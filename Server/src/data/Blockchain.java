package data;

import utils.ByteUtils;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Darstellung der gesamten Blockchain.
 */
public class Blockchain {
    /**
     * Die Datei, in der die Blockchain liegt.
     */
    private final File chain;
    /**
     * Eine Liste mit allen Blöcken der Blockchain.
     */
    private final List<Block> data = new ArrayList<>();

    /**
     * Erzeugt eine Blockchain auf Basis einer Datei.
     *
     * @param chain Die Datei, in der die Blockchain liegt.
     * @throws IOException sollte es irgendwelche Fehler beim Laden geben.
     */
    public Blockchain(File chain) throws IOException {
        this.chain = chain;
        if (chain.exists() && chain.isFile() && chain.length() > 0) {
            try {
                loadFromFile();
            } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
                throw new IOException("Corrupted chain!", e);
            }
        } else if (!chain.createNewFile())
            throw new IOException("Parameter is not a file!");
    }

    /**
     * Erzeugt eine Blockchain auf Basis einer Standarddatei.
     *
     * @throws IOException sollte es irgendwelche Fehler beim Laden geben.
     */
    public Blockchain() throws IOException {
        this(new File("default.chain"));
    }

    /**
     * Lädt die Blockchain aus einer Datei.
     *
     * @throws IOException sollte es irgendwelche Fehler beim Laden geben.
     * @see InvalidKeySpecException
     * @see NoSuchAlgorithmException
     */
    private void loadFromFile() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        DataInputStream in = new DataInputStream(new FileInputStream(chain));
        byte[] buffer = new byte[4];
        while (in.available() > 0) {
            int read = 0;
            do {
                read += in.read(buffer, read, 4 - read);
            } while (read < 4 && in.available() > 0);
            if (in.available() == 0)
                throw new IOException("File is corrupted!");
            byte[] block = readBlock(ByteUtils.toInt(buffer), in);
            data.add(new Block(block));
        }
        if (data.size() > 0) {
            if (!data.get(0).verify(Block.getGenesisHash())) {
                throw new IOException("Invalid Chain!");
            }
            for (int i = 1; i < data.size(); i++) {
                if (!data.get(i).verify(data.get(i - 1).getHash())) {
                    throw new IOException("Invalid Chain!");
                }
            }
        }
    }

    /**
     * Liest einen einzelnen Block ein.
     *
     * @param blockSize Die Größe des Blockes.
     * @param in        Die Quelle, von der der Block gelesen werden soll.
     * @return Den Block als Bytearray.
     * @throws IOException sollte es irgendwelche Fehler beim Laden geben.
     */
    private byte[] readBlock(int blockSize, DataInputStream in) throws IOException {
        byte[] block = new byte[blockSize];
        int read = 0;
        do {
            read += in.read(block, read, blockSize - read);
        } while (read < blockSize && in.available() > 0);
        if (blockSize > read && in.available() == 0)
            throw new IOException("File is corrupted!");
        return block;
    }

    /**
     * Gibt den letzten Hash der Blockchain zurück.
     *
     * @return Der Hash des letzten Blockes.
     */
    public byte[] getLastHash() {
        if (data.size() == 0)
            return Block.getGenesisHash();
        return data.get(data.size() - 1).getHash();
    }

    /**
     * Sucht einen Block mit bestimmtem Hash in der Blockchain.
     *
     * @param hash Der Hash des gesuchten Blockes.
     * @return Der gesuchte Block oder {@code null}, sollte er nicht existieren.
     */
    public Block getBlock(byte[] hash) {
        return data.stream().filter(b -> Arrays.equals(b.getHash(), hash)).findFirst().orElse(null);
    }

    /**
     * Gibt alle Blöcke eines Schülers zurück.
     *
     * @param student Der gesuchte Schüler.
     * @return Die Blöcke des Schülers als Liste.
     */
    public List<Block> getStudentBlocks(PublicKey student) {
        return data.stream().filter(b -> b.getStudent().equals(student)).collect(Collectors.toList());
    }

    /**
     * Überprüft einen Block und fügt diesen zur Blockchain hinzu.
     *
     * @param block Der Block.
     * @return Gibt {@code true} zurück, wenn der Block valide ist und geschrieben werden konnte.
     */
    public boolean verifyAndAdd(byte[] block) {
        Block b;
        try {
            b = new Block(block);
            if (!b.verify(getLastHash())) return false;
        } catch (InvalidKeySpecException | NoSuchAlgorithmException | ArrayIndexOutOfBoundsException e) {
            return false;
        }
        try {
            writeToFile(block);
        } catch (IOException e) {
            return false;
        }
        data.add(b);
        return true;
    }

    /**
     * Schreibt einen Block in die Blockchaindatei.
     *
     * @param block Der Block, der geschrieben werden soll.
     * @throws IOException sollte der Block nicht geschrieben werden können.
     */
    private void writeToFile(byte[] block) throws IOException {
        DataOutputStream out = new DataOutputStream(new FileOutputStream(chain, true));
        out.write(ByteUtils.toBytes(block.length));
        out.write(block);
    }
}
