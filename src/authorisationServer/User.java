package authorisationServer;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Map;


public class User
{
	private static User INSTANCE = null;
	private static String HOST = "localhost";
	private static String PORT = "3306";
	private static String USER = "root";
	private static String PASS = "";
	  
	private static Statement stmt;
	private static PreparedStatement prepStmt;
	private static Connection con;
	
	private String userId="";//will be 'CL'+idClient or 'WS1' or 'WS2' or 'AS'	
	private String publicKey="";
	private String privateKey="";
	private boolean accessWS1=false;
	private boolean accessWS2=false;
	private String saltAsymKey="";
	private String saltSessionKey="";
	private String saltUser="";
	
	private DatabasePassword dbPassword;
	
	public static User getInstance()
	{
		if(INSTANCE==null)		
			INSTANCE = new User();
		
		return INSTANCE;
	}
		   
	private User()
	{
		this.dbPassword = new DatabasePassword();
		
		String url = "jdbc:mysql://"+HOST+":"+PORT+"/User?createDatabaseIfNotExist=true";
		User.con = null;
		User.stmt = null;
		try {
			Class.forName("com.mysql.jdbc.Driver");//load the driver
		    con = DriverManager.getConnection(url,USER,PASS); //connect to mysql
		    this.createTables(); //create tables if not exist :
		    System.out.println("Connected to DB successfully"); //DEBUG
		} catch (SQLException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
		    e.printStackTrace();
		}		 
	}
	
	private void closeStmt()
	{
		if(stmt!=null)
		{
			try 
			{
		       stmt.close();
		    } catch (SQLException e) {
		    	e.printStackTrace();
		    }
		}
		
		if(prepStmt!=null)
		{
			try
			{
		       prepStmt.close();
		    } catch (SQLException e) {
		         e.printStackTrace();
		    }
		 }
	}
	
	public void closeConnection()
	{
		if(con!=null) 
		{
			try 
			{
				con.close();
				System.out.println("Closed DB connection successfully");
			} catch (SQLException e) {
		         e.printStackTrace();
			}
	     }	
	}
	
	private boolean createTables()
	{
		return true;
	}
	
	/**
	 * Take all the information for the user (access to WS1 or WS2 valid), only called if this is client
	 * @param userId (int! not 'CL'+id)
	 * @return boolean
	 */
	public boolean getUser(int userId) 
	{		
		String temp="";
		//We take all the information directly
		String sql = "SELECT u.* FROM info405.user u WHERE u.id="+userId;
		
		//    System.out.println(sql); //DEBUG
		ResultSet rs;
		try 
		{
			stmt = con.createStatement();
		    rs = stmt.executeQuery(sql);
		    		    	
		    //We take the salt
		    this.saltUser = rs.getString("salt");
		    
		    //We take the WS1
		    temp = rs.getString("WS1");
		    temp = this.dbPassword.decrypt("WS1",temp, this.saltUser);
		    if("1".equals(temp))
		    	this.accessWS1 = true;
		    else
		    	this.accessWS1 = false;
		    

		    //We take the WS2
		    temp = rs.getString("WS2");
		    temp = this.dbPassword.decrypt("WS2",temp, this.saltUser);
		    if("1".equals(temp))
		    	this.accessWS2 = true;
		    else
		    	this.accessWS2 = false;  		    
		} catch (SQLException e) {
			e.printStackTrace();
		    return false;
		} finally {
			this.closeStmt();  
		}
		     
		return true;
	}
	
	/**
	 * Take the information for the asymmetric keys from the db
	 * @param owner String ('CL'+id or 'AS' or 'WS1' or 'WS2')
	 * @return boolean
	 */
	public boolean getAsymKey(String owner)
	{
		String temp="";
		
		//We take all the information directly
		String sql = "SELECT a.* FROM info405.asymkey u WHERE validity=1 AND a.owner="+owner;
		
		//    System.out.println(sql); //DEBUG
		ResultSet rs;
		try 
		{
			stmt = con.createStatement();
		    rs = stmt.executeQuery(sql);
		    		    	
		    //We take the salt
		    this.saltAsymKey = rs.getString("salt");
		    
		    //We take the public key
		    temp = rs.getString("publicKey");
		    this.publicKey = this.dbPassword.decrypt("publicKey", temp, this.saltAsymKey);

		    //We take the private key (it does not exist always)
		    if("AS".equals(owner))
		    {
		    	temp = rs.getString("privateKey");
		    	this.privateKey = this.dbPassword.decrypt("privateKey", temp, this.saltAsymKey);
		    }
		    
		} catch (SQLException e) {
			e.printStackTrace();
		    return false;
		} finally {
			this.closeStmt();  
		}
		     
		return true;
	}
	
	/**
	 * Take the session key for AS or WS (always the same) and give it back
	 * @param owner String ('CL'+id or 'AS' or 'WS1' or 'WS2')
	 * @return String
	 */
	public String getSessionKeyServer(String owner)
	{
		return "";
	}
	
	/**
	 * Insert a new session key into the db for the current user
	 * @param value String well, we could put an empty string as we won't this key again...
	 * @param boolean 
	 */
	public boolean insertNewSessionKey()
	{
		return true;
	}
	
	/**
	 * Revoke all the old session keys for the specified destination with the current user
	 * @param destination String
	 * @return
	 */
	public boolean revokeOldSessionKeys(String destination)
	{
		return true;
	}

	
	/**
	 * Just says if the user can access to the WS1
	 * @return boolean
	 */
	public boolean getAccessWS1()
	{
		return this.accessWS1;
	}
	
	/**
	 * Just says if the user can access to the WS2
	 * @return boolean
	 */
	public boolean getAccessWS2()
	{
		return this.accessWS2;
	}
}
