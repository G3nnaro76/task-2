package it.unisa.model;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import javax.sql.DataSource;
import org.mindrot.jbcrypt.BCrypt;

public class UserDao {
    private DataSource ds;

    public UserDao(DataSource ds) {
        this.ds = ds;
    }

    // Metodo per salvare un nuovo utente con password hashata
    public void saveUser(UserBean user) throws SQLException {
        String hashedPassword = BCrypt.hashpw(user.getPassword(), BCrypt.gensalt());

        String query = "INSERT INTO users (username, password) VALUES (?, ?)";
        try (Connection connection = ds.getConnection();
             PreparedStatement ps = connection.prepareStatement(query)) {
            ps.setString(1, user.getUsername());
            ps.setString(2, hashedPassword);
            ps.executeUpdate();
        }
    }

    // Metodo per recuperare un utente e verificare la password
    public UserBean doRetrieve(String username, String password) throws SQLException {
        UserBean user = new UserBean();
        String query = "SELECT * FROM users WHERE username = ?";
        try (Connection connection = ds.getConnection();
             PreparedStatement ps = connection.prepareStatement(query)) {
            ps.setString(1, username);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    String storedHash = rs.getString("password");
                    if (BCrypt.checkpw(password, storedHash)) {
                        user.setUsername(rs.getString("username"));
                        user.setValid(true);
                    }
                }
            }
        }
        return user;
    }
}
