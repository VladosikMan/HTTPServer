package server;

import java.io.IOException;

public class ServerHTTPD extends NanoHTTPD {
    //К
    public ServerHTTPD(int port) throws IOException {
        super(port);
        start(NanoHTTPD.SOCKET_READ_TIMEOUT, false);

    }
    public static void main(String[] args) {
         try {
             new ServerHTTPD(8080);

         } catch (IOException e) {
             e.printStackTrace();
         }
     }

    @Override
    public Response serve(IHTTPSession session) {
        return super.serve(session);
    }

}