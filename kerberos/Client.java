package com.coolsnow.cs2.service;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.PrivilegedAction;
import java.util.Properties;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

import sun.misc.BASE64Encoder;

public class Client {
	 
	  public static void main( String[] args) {
	    try {
	      // Setup up the Kerberos properties.
//	      Properties props = new Properties();
//	      props.load( new FileInputStream( "client.properties"));
	      System.setProperty( "sun.security.krb5.debug", "true");
	      System.setProperty( "java.security.krb5.realm", "REDHAT.COM"); 
	      System.setProperty( "java.security.krb5.kdc", "kerberos01.core.prod.int.sin2.redhat.com.:88");
	      System.setProperty( "java.security.auth.login.config", "/home/ltian/work/code/cs2/src/main/java/com/coolsnow/cs2/service/jaas.conf");
	      System.setProperty( "javax.security.auth.useSubjectCredsOnly", "true");
	      String username = "ltian5";
	      String password = "yourpwd";
	      // Oid mechanism = use Kerberos V5 as the security mechanism.
	      krb5Oid = new Oid( "1.2.840.113554.1.2.2");
	      Client client = new Client();
	      // Login to the KDC.
	      client.login( username, password);
	      System.out.println("---- "+client.subject);
	      // Request the service ticket.
//	      client.initiateSecurityContext( "krbtgt/REDHAT.COM@REDHAT.COM");
	      // Write the ticket to disk for the server to read.
//	      encodeAndWriteTicketToDisk( client.serviceTicket, "./security.token");
	      System.out.println( "Service ticket encoded to disk successfully");
	    }
	    catch ( LoginException e) {
	      e.printStackTrace();
	      System.err.println( "There was an error during the JAAS login");
	      System.exit( -1);
	    }
	    catch ( GSSException e) {
	      e.printStackTrace();
	      System.err.println( "There was an error during the security context initiation");
	      System.exit( -1);
	    }
//	    catch ( IOException e) {
//	      e.printStackTrace();
//	      System.err.println( "There was an IO error");
//	      System.exit( -1);
//	    }
	  }
	 
	  public Client() {
	    super();
	  }
	 
	  private static Oid krb5Oid;
	 
	  private Subject subject;
	  private byte[] serviceTicket;
	 
	  // Authenticate against the KDC using JAAS.
	  private void login( String username, String password) throws LoginException {
	    LoginContext loginCtx = null;
	    // "Client" references the JAAS configuration in the jaas.conf file.
	    loginCtx = new LoginContext( "Client",
	        new LoginCallbackHandler( username, password));
	    loginCtx.login();
	    this.subject = loginCtx.getSubject();
	  }
	 
	  // Begin the initiation of a security context with the target service.
	  private void initiateSecurityContext( String servicePrincipalName)
	      throws GSSException {
	    GSSManager manager = GSSManager.getInstance();
	    GSSName serverName = manager.createName( servicePrincipalName,
	        GSSName.NT_HOSTBASED_SERVICE);
	    final GSSContext context = manager.createContext( serverName, krb5Oid, null,
	        GSSContext.DEFAULT_LIFETIME);
	    // The GSS context initiation has to be performed as a privileged action.
	    this.serviceTicket = Subject.doAs( subject, new PrivilegedAction<byte[]>() {
	      public byte[] run() {
	        try {
	          byte[] token = new byte[0];
	          // This is a one pass context initialisation.
	          context.requestMutualAuth( false);
	          context.requestCredDeleg( false);
	          return context.initSecContext( token, 0, token.length);
	        }
	        catch ( GSSException e) {
	          e.printStackTrace();
	          return null;
	        }
	      }
	    });
	 
	  }
	 
	  // Base64 encode the raw ticket and write it to the given file.
	  private static void encodeAndWriteTicketToDisk( byte[] ticket, String filepath)
	      throws IOException {
	    BASE64Encoder encoder = new BASE64Encoder();    
	    FileWriter writer = new FileWriter( new File( filepath));
	    String encodedToken = encoder.encode( ticket);
	    writer.write( encodedToken);
	    writer.close();
	  }
    
	@GET
	@POST
    	@Path("/advisory/kerberos")
    public Response kerberos1(@Context UriInfo uI) throws DataServiceException {
		Map<String,String> map = new HashMap<String, String>();
		map.put("code", "200");
		MultivaluedMap<String, String> params = uI.getQueryParameters();
		String username = params.getFirst("j_username");
		String password = params.getFirst("j_password");
		LOGGER.info( "username : "+username + " password : "+password);
        BASE64Decoder decoder = new BASE64Decoder();  
        
        try{
	        byte[] b = decoder.decodeBuffer(password);  
	        password = new String(b, "utf-8");  
        }catch(Exception e){
        	
        }
		LOGGER.info( "username : "+username + " password : "+password);
		Client client = new Client();
	      // Login to the KDC.
	      try {
			client.login( username, password);
		} catch (LoginException e) {
			map.put("code", "401");
			e.printStackTrace();
		}
        String result = new GsonBuilder().excludeFieldsWithoutExposeAnnotation().create().toJson(map);
        System.out.println("---- "+client.subject);
        return Response.ok(result).build();
    }
	}
