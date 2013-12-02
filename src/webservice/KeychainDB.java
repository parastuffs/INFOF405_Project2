package webservice;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;

public class KeychainDB {

	private static KeychainDB INSTANCE = null;
	private static String HOST = "localhost";
	private static String PORT = "3306";
	private static String USER = "root";
	private static String PASS = "";
	
	private static Statement stmt;
	private static PreparedStatement prepStmt;
	private static Connection con;
	
	public static KeychainDB getInstance() {
		if(INSTANCE==null) {
			INSTANCE = new KeychainDB();
		}
		return INSTANCE;
	}
	
	private KeychainDB() {
		String url = "jdbc:mysql://"+HOST+":"+PORT+"/Keychain?createDatabaseIfNotExist=true";
		KeychainDB.con = null;
		KeychainDB.stmt = null;
		try {
			Class.forName("com.mysql.jdbc.Driver");//load the driver
			con = DriverManager.getConnection(url,USER,PASS); //connect to mysql
			this.createTable(); //create tables if not exist :
			System.out.println("Connected to KeychainDB successfully"); //DEBUG
		} catch (SQLException e) {
				e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}

	}
	
	private void createTable() {
		String sql = "CREATE TABLE IF NOT EXISTS Keychain.Passwords (" +
				"ID INT NOT NULL AUTO_INCREMENT," +
				"ClientID INT NOT NULL," +
				"Pass VARCHAR(255) NOT NULL," +
				"PRIMARY KEY(ID)" +
				") ENGINE=InnoDB;";
		try {
			stmt = con.createStatement();
			stmt.executeUpdate(sql);
		} catch (SQLException e) {
			e.printStackTrace();
		} finally {
			this.closeStmt();
		}
	}

	private void closeStmt() {
		if(stmt!=null) {
			try {
				stmt.close();
			} catch (SQLException e) {
				e.printStackTrace();
			}
		}
		if(prepStmt!=null) {
			try {
				prepStmt.close();
			} catch (SQLException e) {
				e.printStackTrace();
			}
		}
	}
	
	public void closeConnection() {
		if(con!=null) {
			try {
				con.close();
				System.out.println("Closed DB connection successfully");
			} catch (SQLException e) {
				e.printStackTrace();
			}
		}
	}

	/**
	 * Returns all the passwords of a client stored in the keychain
	 * @param clientID
	 * @return Returns an ArrayList of passwords; might be empty; null if an error occured
	 */
	public ArrayList<String> getMyPasses(int clientID) {
		ArrayList<String> res = new ArrayList<String>();
		String sql = "SELECT k.Pass FROM Keychain.Passwords k WHERE k.ClientID="+clientID;
		System.out.println(sql); //DEBUG
		ResultSet rs;
		try {
			stmt = con.createStatement();
			rs = stmt.executeQuery(sql);
			while (rs.next()) {
				String s = new String(rs.getString("Pass")); 
				res.add(s);
				System.out.println("found : string="+s);
			}
			if(res.isEmpty())
				System.out.println("EMPTY ResultSet");
			System.out.println("GetMyPosts = success"); //DEBUG
		} catch (SQLException e) {
			e.printStackTrace();
			return null;
		} finally {
			this.closeStmt();	
		}
		
		return res;
	}
	
	public boolean addNewPass(int clientID, String pass) {
		String sql = "INSERT INTO Keychain.Passwords (ClientID,Pass) VALUES (?,?)";
		int lines;
		try {
			prepStmt = con.prepareStatement(sql);
			prepStmt.setInt(1,clientID);
			prepStmt.setString(2, pass);
			System.out.println(prepStmt.toString());//DEBUG
			lines = prepStmt.executeUpdate();
			System.out.println("modified nb lines :"+lines); //DEBUG
		} catch (SQLException e) {
			e.printStackTrace();
			return false;
		} finally {
			this.closeStmt();
		}
		if(lines>0)
			return true;
		else 
			return false;
	}
}
