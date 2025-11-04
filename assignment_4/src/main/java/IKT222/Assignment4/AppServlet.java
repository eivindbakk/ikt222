package IKT222.Assignment4;

import java.io.File;
import java.io.IOException;
import java.sql.*;
import java.util.*;

import javax.servlet.ServletException;
import javax.servlet.http.*;

import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import freemarker.template.TemplateExceptionHandler;

@SuppressWarnings("serial")
public class AppServlet extends HttpServlet {

    private static final String CONNECTION_URL = "jdbc:sqlite:db.sqlite3";

    // bcrypt-only auth (no plaintext):
    private static final String AUTH_QUERY =
            "select id, password_hash from user where username = ? limit 1";

    // WI-2-safe (scoped by gp_id = userId)
    private static final String SEARCH_QUERY =
            "select id, surname, forename, address, born, gp_id, treated_for " +
                    "from patient where surname like ? and gp_id = ?";

    private final Configuration fm = new Configuration(Configuration.VERSION_2_3_28);
    private Connection database;

    @Override
    public void init() throws ServletException {
        configureTemplateEngine();
        connectToDatabase();
        // Assumes DB already has user(password_hash) and (optionally) no plaintext column.
        // If not, run DbPasswordMigrator once (see file below).
    }

    private void configureTemplateEngine() throws ServletException {
        try {
            fm.setDirectoryForTemplateLoading(new File("./templates"));
            fm.setDefaultEncoding("UTF-8");
            fm.setTemplateExceptionHandler(TemplateExceptionHandler.HTML_DEBUG_HANDLER);
            fm.setLogTemplateExceptions(false);
            fm.setWrapUncheckedExceptions(true);
            fm.setFallbackOnNullLoopVariable(false);
        } catch (IOException error) {
            throw new ServletException(error.getMessage());
        }
    }

    private void connectToDatabase() throws ServletException {
        try {
            database = DriverManager.getConnection(CONNECTION_URL);
            try (Statement s = database.createStatement()) {
                s.execute("PRAGMA foreign_keys = ON");
            }
            // small hardening: index on username for faster lookups (no-op if exists)
            try (Statement s = database.createStatement()) {
                s.execute("CREATE INDEX IF NOT EXISTS idx_user_username ON user(username)");
            }
        } catch (SQLException error) {
            throw new ServletException(error.getMessage());
        }
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        try {
            Template template = fm.getTemplate("login.html");
            template.process(null, response.getWriter());
            response.setContentType("text/html");
            response.setStatus(HttpServletResponse.SC_OK);
        } catch (TemplateException error) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * POST handles login + owner-scoped search.
     * 1) If a session exists with userId -> use it.
     * 2) Else, authenticate using bcrypt (username -> id, password_hash; verify).
     * 3) Perform surname search restricted to gp_id = userId (WI-2).
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        final String username = trim(request.getParameter("username"));
        final String password = trim(request.getParameter("password"));
        final String surname  = trim(request.getParameter("surname"));

        try {
            Map<String, Object> model = new HashMap<>();

            // Reuse session if available
            HttpSession session = request.getSession(false);
            Integer userId = (session != null) ? asInteger(session.getAttribute("userId")) : null;

            // Authenticate if no session and user supplied creds
            if (userId == null && username != null && password != null) {
                userId = authenticate(username, password);
                if (userId != null) {
                    session = request.getSession(true);
                    session.setAttribute("userId", userId);
                }
            }

            // Unauthenticated -> show invalid page
            if (userId == null) {
                Template template = fm.getTemplate("invalid.html");
                template.process(model, response.getWriter());
                response.setContentType("text/html");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }

            // Owner-scoped search (prevents IDOR)
            List<Record> results = searchResults(surname, userId);
            model.put("records", results);
            model.put("surname", surname);

            Template template = fm.getTemplate("details.html");
            template.process(model, response.getWriter());
            response.setContentType("text/html");
            response.setStatus(HttpServletResponse.SC_OK);

        } catch (TemplateException error) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        } catch (SQLException error) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, error.getMessage());
        }
    }

    /** bcrypt-only authentication: fetch hash and verify. */
    private Integer authenticate(String username, String candidatePassword) throws SQLException {
        try (PreparedStatement ps = database.prepareStatement(AUTH_QUERY)) {
            ps.setString(1, username);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) return null;
                int id = rs.getInt("id");
                String storedHash = rs.getString("password_hash");
                if (storedHash == null || storedHash.isEmpty()) return null;
                return PasswordUtil.verify(candidatePassword, storedHash) ? id : null;
            }
        }
    }

    /** Search patients by surname, restricted to gp_id == userId (WI-2). */
    private List<Record> searchResults(String surname, int userId) throws SQLException {
        List<Record> records = new ArrayList<>();
        String like = "%" + (surname == null ? "" : surname) + "%";
        try (PreparedStatement ps = database.prepareStatement(SEARCH_QUERY)) {
            ps.setString(1, like);
            ps.setInt(2, userId);
            try (ResultSet r = ps.executeQuery()) {
                while (r.next()) {
                    Record rec = new Record();
                    rec.setSurname(r.getString("surname"));
                    rec.setForename(r.getString("forename"));
                    rec.setAddress(r.getString("address"));
                    rec.setDateOfBirth(r.getString("born"));
                    rec.setDoctorId(Integer.toString(r.getInt("gp_id")));
                    rec.setDiagnosis(r.getString("treated_for"));
                    records.add(rec);
                }
            }
        }
        return records;
    }

    // --- utils --

    private static String trim(String s) {
        return s == null ? null : s.trim();
    }

    private static Integer asInteger(Object o) {
        return (o instanceof Integer) ? (Integer)o : null;
    }
}
