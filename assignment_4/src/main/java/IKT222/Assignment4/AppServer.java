package IKT222.Assignment4;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;

/**
 * AppServer (Option A)
 *
 * Simple Jetty bootstrap that enables servlet sessions by creating a
 * ServletContextHandler with the SESSIONS flag. This will ensure
 * request.getSession(true) and request.getSession(false) work.
 *
 * Replace your existing AppServer.java with this file (same package),
 * then rebuild and run the project.
 */
public class AppServer {

    public static void main(String[] args) throws Exception {
        // Listen on 8080 (same as original)
        Server server = new Server(8080);

        // Enable sessions on the context
        ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
        context.setContextPath("/");

        // Register our servlet at root path
        context.addServlet(new ServletHolder(new AppServlet()), "/");

        // Attach the context to the server and start
        server.setHandler(context);
        server.start();
        server.join();
    }
}
