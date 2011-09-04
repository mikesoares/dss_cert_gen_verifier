/****************************************
 *
 * DSS-Based Mini-Certificate Generation
 * Server Code
 *
 * @author Michael A. Soares
 * @date July 20, 2011
 *
 ****************************************/

/*
	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

import java.math.BigInteger;
import java.net.*;
import java.io.*;

public class Server { 
	// for debugging
	private static final boolean DEBUG = false;
	
	private static Socket s;
	private static ServerSocket ss;
	private static ObjectOutputStream out;
	private static ObjectInputStream in;
	private static String message;
	
	public static void main(String[] args) throws Exception {
		Server server = new Server();
		while(true) {
			server.run();	// let's run this server until we forcefully exit
		}
	}
	
	// runs each of the functions needed for generating and validating certificates - communicates with client
	private static void run() throws Exception {
		BigInteger pkClient;
		String id, expiry;
		Cert cert = null;	// create a null certificate right now until we're ready to generate or verify one
		DSSSig common = new DSSSig();	// create a new object to take care of computations for certificate
		BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
		
		// check our system parameters - these are in the DSSig object
		if(common.checkValues()) {
			System.out.println("server> System parameters are valid. Continuing...");
		} else {
			System.out.println("server> System parameters are NOT valid. Stopping...");
			return;
		}
		
		// start our server and communication with the client
		try {
		    ss = new ServerSocket(31337);
			System.out.println("server> Waiting for request...");
			s = ss.accept();
			System.out.println("server> Connection received from " + s.getInetAddress().getHostName() + ".");
			out = new ObjectOutputStream(s.getOutputStream());
			out.flush();
			in = new ObjectInputStream(s.getInputStream());
			
			message = (String)in.readObject();	// this will be the public key
			pkClient = new BigInteger(message);
			System.out.println("server> Public key received.");
			
			sendMessage("server> Got your public key.\r\nserver> What do you want to do?:\r\nserver> 1) Generate a certificate\r\nserver> 2) Verify a certificate\r\nserver> Press any other key, then press 'Enter' to exit.");					
			message = (String)in.readObject();
			
			if(message.equals("1")) {	// this option prompts the user for info to generate a certificate
				sendMessage("server> 1 selected.\r\nserver> Please enter your identity (10 characters max):");
				id = (String)in.readObject();

				// make sure the ID actually contains characters and is less than 10 characters
				if(id.length() <= 0 || id.length() > 10) {
					sendMessage("server> ID was in wrong format. Press 'Enter' to exit and start over.");
					System.out.println("server> Identity was in wrong format. Exiting...");
					sendMessage("exit");
					closeConnection();
					return;
				} else {
					sendMessage("server> Thanks.\r\nserver> Hit 'Enter' when the CA has finished entering expiry date.");
					System.out.println("server> Identity received.");
				}
				
				System.out.println("server> Enter an expiry date for certificate (yyyy-mm-dd):");
				expiry = reader.readLine();
				System.out.println("server> Waiting for client to hit 'Enter'...");
				message = (String)in.readObject();
				
				// make sure our expiry date character length is exactly 10 characters (correct format)
				if(expiry.length() != 10) {
					sendMessage("server> CA entered expiry date.\r\nserver> Expiry date was invalid.\r\nserver> Press 'Enter' to exit and start over.");
					System.out.println("server> Expiry date was in wrong format. Exiting...");
					message = (String)in.readObject();
					sendMessage("exit");
					closeConnection();
					return;
				} else {
					common.setExpiry(expiry);	// set our expiry date
					sendMessage("server> CA entered expiry date.\r\nserver> Expiry date was set to: " + common.getExpiry() + ".\r\nserver> Press 'Enter' to continue.");
				}
				
				message = (String)in.readObject();
				cert = common.generateCert(id, pkClient);	// generate a certificate
				sendMessage("server> Your mini-certificate is below:\r\n---------- START CERTIFICATE ----------\r\n" + cert.getM() + "\n" + cert.getR().toString() + "\n" + cert.getS().toString() + "\r\n----------- END CERTIFICATE -----------\r\nserver> Press 'Enter' to exit.");
			} else if(message.equals("2")) {	// this option prompts the user for certificate information to verify
				String line1;
				BigInteger line2, line3;
				sendMessage("server> 2 selected.\r\nserver> Please paste in your certificate below one line at a time, starting with Line 1 (exluding the START/END lines):");
				line1 = (String)in.readObject();
				sendMessage("server> Line 2:");
				line2 = new BigInteger((String)in.readObject());
				sendMessage("server> Line 3:");
				line3 = new BigInteger((String)in.readObject());
				cert = new Cert(line1, line2, line3);
				
				if(common.verifyCert(cert)) {	// verify the certificate
					sendMessage("server> Your certificate is valid.\r\nPress 'Enter' to exit.");
					System.out.println("server> User entered valid certificate.");
				} else {
					sendMessage("server> Your certificate is NOT valid.\r\nPress 'Enter' to exit.");
					System.out.println("server> User entered INVALID certificate.");
				}
			} else {	// forcefully exit
				sendMessage("exit-force");
				closeConnection();
				System.exit(0);
			}
			
			sendMessage("exit");
		} catch(ClassNotFoundException classnot) {
			System.err.println("server>Data received in unknown format.");
		} catch(IOException e) {
		    System.err.println("server>Connection closed.");
		    System.exit(-1);
		}
		
		closeConnection();
	}
	
	// close our connection properly
	private static void closeConnection() {
		try {
			in.close();
			out.close();
			ss.close();
		} catch(IOException e) {
			e.printStackTrace();
		}
		
		System.out.println("server> Connection closed.");
	}
	
	// for sending messages
	private static void sendMessage(String msg) {
		try {
			out.writeObject(msg);
			out.flush();
		} catch(IOException e) {
			e.printStackTrace();
		}
	}
}
