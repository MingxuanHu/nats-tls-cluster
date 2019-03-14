import io.nats.client.Connection;
import io.nats.client.Nats;
import io.nats.client.Options;

import javax.net.ssl.*;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.SecureRandom;

public class Client {
    private static String PRIVSTORE_PATH = "src/main/resources/certs/privstore.ks";
    private static String TRUSTSTORE_PATH = "src/main/resources/certs/truststore.ks";
    private static String STORE_PASSWORD = "password";
    private static String KEY_PASSWORD = "password";
    private static String ALGORITHM = "SunX509";

    public static void main(String... args) throws Exception {
        Options options = new Options.Builder().
                server("nats://10.80.28.46:4222").
                sslContext(createContext()).
                build();
        Connection nc = Nats.connect(options);

        // do something with the connection

        nc.close();
    }

    private static SSLContext createContext() throws Exception {
        SSLContext ctx = SSLContext.getInstance(Options.DEFAULT_SSL_PROTOCOL);
        ctx.init(createPrivateKeyManagers(), createTrustManagers(), new SecureRandom());
        return ctx;
    }

    private static KeyManager[] createPrivateKeyManagers() throws Exception {
        KeyStore store = loadKeystore(PRIVSTORE_PATH);
        KeyManagerFactory factory = KeyManagerFactory.getInstance(ALGORITHM);
        factory.init(store, KEY_PASSWORD.toCharArray());
        return factory.getKeyManagers();
    }

    private static TrustManager[] createTrustManagers() throws Exception {
        KeyStore store = loadKeystore(TRUSTSTORE_PATH);
        TrustManagerFactory factory = TrustManagerFactory.getInstance(ALGORITHM);
        factory.init(store);
        return factory.getTrustManagers();
    }

    private static KeyStore loadKeystore(String path) throws Exception {
        KeyStore store = KeyStore.getInstance("JKS");
        BufferedInputStream in = null;
        try {
            in = new BufferedInputStream(new FileInputStream(path));
            store.load(in, STORE_PASSWORD.toCharArray());
        } finally {
            if (in != null) {
                in.close();
            }
        }
        return store;
    }
}
