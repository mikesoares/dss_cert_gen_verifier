/****************************************
 *
 * DSS-Based Mini-Certificate Generation
 * Client Code
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

import java.util.Random;
import java.math.BigInteger;
import java.io.*;
import java.net.*;

public class Client { 
	// for debugging
	private static final boolean DEBUG = false;
	
	private static Socket s;
	private static ObjectOutputStream out;
	private static ObjectInputStream in;
	private static String message;
	
	public static void run() {
		BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));;
		String server = "";
		int port = 31337;
		System.out.print("client> Enter server address: ");
		
		try {
			server = reader.readLine();
		} catch(IOException e) {
			System.err.println("client> Error reading input.");
			System.exit(-1);
		}
		
		try {
			s = new Socket(server, port);
			System.out.println("client> Connected to " + server + " on port " + port + ".");
			out = new ObjectOutputStream(s.getOutputStream());
			out.flush();
			in = new ObjectInputStream(s.getInputStream());

			try {
				BigInteger pkClient = BigInteger.ZERO;

				while(pkClient.bitLength() != 1024) {
					pkClient = new BigInteger(1025, new Random()); // randomly generated client public key (128 bytes)
				}
				
				sendMessage(pkClient.toString());
				System.out.println("client> Sent public key.");
				
				// just loop, receive and send messages from/to the server until we get back a message to exit or forcefully exit
				while(true) {
					message = (String)in.readObject();
					
					if(message.equals("exit")) {
						break;
					} else if(message.equals("exit-force")) {
						closeConnection();
						System.exit(0);
					}
					
					System.out.println(message);
					message = reader.readLine();
					sendMessage(message);
				}
			} catch(ClassNotFoundException e){
				System.err.println("client> Data received in unknown format!");
			}

			closeConnection();
		} catch(UnknownHostException e){
			System.err.println("client> You are trying to connect to an unknown host!");
		} catch(IOException e){
			e.printStackTrace();
		}
	}

	// close our connection properly
	private static void closeConnection() {
		try {
			in.close();
			out.close();
			s.close();
		} catch(IOException e) {
			e.printStackTrace();
		}
		
		System.out.println("client> Connection closed.");
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
	
	public static void main(String args[]) {
		Client client = new Client();
		while(true) {
			client.run();
		}
	}
}
