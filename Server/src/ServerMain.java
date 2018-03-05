import data.Blockchain;
import network.ConnectionHandler;

import java.io.File;
import java.io.IOException;

@SuppressWarnings("WeakerAccess")
public class ServerMain {
    public static void main(String[] args) throws IOException {
        if (args.length == 0) {
            System.err.println("Usage: java -jar this.jar port [file]");
            return;
        }
        Blockchain c;
        if (args.length == 2) {
            c = new Blockchain(new File(args[1]));
        } else {
            c = new Blockchain();
        }
        ConnectionHandler con = new ConnectionHandler(Integer.parseInt(args[0]), c);
        System.out.println("Server successfully started!");
    }
}
