package network;

import data.Blockchain;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Verwaltet sämtliche Verbindungen.
 */
public class ConnectionHandler {
    /**
     * Alle Clients.
     */
    private final ArrayList<Client> clients;

    /**
     * Erzeugt ein neues Objekt, das auf einem gewissen Port und mit einer gewissen Blockchain arbeitet.
     *
     * @param port  Der Port, der verwendet werden soll.
     * @param chain Die Blockchain.
     */
    public ConnectionHandler(int port, Blockchain chain) {
        clients = new ArrayList<>();
        Thread acceptor = new Thread(() -> acceptClients(port, chain));
        acceptor.setDaemon(true);
        acceptor.start();
        ScheduledExecutorService listener = Executors.newSingleThreadScheduledExecutor();
        listener.scheduleWithFixedDelay(this::traverseAllClients, 0, 500, TimeUnit.MILLISECONDS);
    }

    /**
     * Ruft bei für jeden Client seine {@code handle} Methode auf.
     */
    private void traverseAllClients() {
        //Würde eine forEach Schleife verwendet,
        //könnte das Programm durch das Schließen einer Verbindung zum Absturz gebracht werden.
        //noinspection ForLoopReplaceableByForEach
        for (int i = 0; i < clients.size(); i++) {
            clients.get(i).handle();
        }
    }

    /**
     * Versucht dauerhaft neue Verbindungen anzunehmen.
     *
     * @param port  Der Port, auf dem gesucht wird.
     * @param chain Die Blockchain, mit der die neuen Clients arbeiten sollen.
     */
    private void acceptClients(int port, Blockchain chain) {
        ServerSocket soc = null;
        try {
            soc = new ServerSocket(port);
        } catch (IOException e) {
            System.err.println("Fehler beim Erstellen des Servers: " + e.getLocalizedMessage());
            System.exit(1);
        }
        while (!Thread.interrupted()) {
            try {
                Socket s = soc.accept();
                s.setSoTimeout(500);
                addClient(new Client(s, chain, this::removeClient));
            } catch (IOException e) {
                System.err.println("Fehler beim Erstellen einer Clientverbindung: " + e.getLocalizedMessage());
            }
        }
        try {
            soc.close();
        } catch (IOException e) {
            System.err.println("Fehler beim Schließen des Servers: " + e.getLocalizedMessage());
        }
    }

    /**
     * Fügt einen Client in die Liste aller Clients hinzu.
     *
     * @param client Der neue Client.
     */
    private void addClient(Client client) {
        synchronized (clients) {
            clients.add(client);
        }
    }

    /**
     * Entfernt einen Client aus der Liste aller Clients.
     *
     * @param client Der zu entfernende Client.
     */
    @SuppressWarnings("WeakerAccess")
    public void removeClient(Client client) {
        synchronized (clients) {
            clients.remove(client);
        }
    }
}
