/****************************************
 *
 * DSS-Based Mini-Certificate Generation
 * DSS Signature Code
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
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.Calendar;

public class DSSSig { 
	// for debugging
	private static final boolean DEBUG = false;
	
	// system parameters, as defined in the assignment
    private static final BigInteger 
        p = new BigInteger("168199388701209853920129085113302407023173962717160229197318545484823101018386724351964316301278642143567435810448472465887143222934545154943005714265124445244247988777471773193847131514083030740407543233616696550197643519458134465700691569680905568000063025830089599260400096259430726498683087138415465107499"),
        q = new BigInteger("959452661475451209325433595634941112150003865821"),
        g = new BigInteger("94389192776327398589845326980349814526433869093412782345430946059206568804005181600855825906142967271872548375877738949875812540433223444968461350789461385043775029963900638123183435133537262152973355498432995364505138912569755859623649866375135353179362670798771770711847430626954864269888988371113567502852");
    
    // CA public and private keys, as defined in the assignment
    private static final BigInteger
        skCA = new BigInteger("432398415306986194693973996870836079581453988813"),
        pkCA = new BigInteger("49336018324808093534733548840411752485726058527829630668967480568854756416567496216294919051910148686186622706869702321664465094703247368646506821015290302480990450130280616929226917246255147063292301724297680683401258636182185599124131170077548450754294083728885075516985144944984920010138492897272069257160");
	
	private static String expiryDate = "";
	
	// empty constructor
	public DSSSig() throws Exception {
		// nothing
	}

	// just an intermediate function for generating a certificate
	public static Cert generateCert(String id, BigInteger pkClient) throws Exception {
		if(DEBUG) {
			System.out.println("expiry: " + getExpiry());
		}
		
		return computeRS(id + pkClient.toString() + getExpiry());
	}
	
	// generates our certificate
	private static Cert computeRS(String m) throws Exception {
		boolean range = false;
		BigInteger
			k = BigInteger.ZERO,
			h = hashMsg(m),
			r = BigInteger.ZERO,
			s = BigInteger.ZERO;
		
		if(DEBUG) {
			System.out.println("h: " + h.toString());
		}
		
		// calculate k, r, and s until all three values are in the correct ranges, then break from the loop
		while(!range) {
            k = new BigInteger(161, new Random());
			r = g.modPow(k, p).mod(q);
			s = h.add(skCA.multiply(r)).multiply(k.modInverse(q)).mod(q);

			// check if k is within the correct range and r and s are the correct length (160 bits) - as per the algorithm in the book
            if(k.compareTo(q) < 0 && k.compareTo(BigInteger.ZERO) > 0 && r.bitLength() == 160 && s.bitLength() == 160) {
                range = true;
            } else if(r.bitLength() == 0 || s.bitLength() == 0) {
				range = false;
			}
        }
		
		if(DEBUG) {
			System.out.println("k: " + k.toString());
			System.out.println("r: " + r.toString());
	        System.out.println("s: " + s.toString());
		}
		
		return new Cert(m, r, s);
	}
	
	public static boolean verifyCert(Cert cert) throws Exception {
		BigInteger w, u1, u2, v;
		
		// make sure our values in the correct ranges
		if((cert.getR().compareTo(q) >= 0 && cert.getR().compareTo(BigInteger.ZERO) <= 0) || (cert.getS().compareTo(q) >= 0 && cert.getS().compareTo(BigInteger.ZERO) <= 0)) {
			return false;
		}
		
		// now calculcate all the values we need for this
		w = cert.getS().modInverse(q);
		u1 = w.multiply(hashMsg(cert.getM())).mod(q);
		u2 = w.multiply(cert.getR()).mod(q);
		v = g.modPow(u1, p).multiply(pkCA.modPow(u2, p)).mod(p).mod(q);
		
		if(v.compareTo(cert.getR()) == 0) {
			return true;
		}
		
		return false;
	}

	// check each of our system parameters and the keypair
	public static boolean checkValues() {
		boolean flag = true;
		
		if(!checkP()) {
			if(DEBUG) {
				System.out.println("p value is NOT valid.");
			}
			
			flag = false;
		} else {
			if(DEBUG) {
				System.out.println("p value is valid.");
			}
		}
		
		if(!checkQ()) {
			if(DEBUG) {
				System.out.println("q value is NOT valid.");
			}
			
			flag = false;
		} else {
			if(DEBUG) {
				System.out.println("q value is valid.");
			}
		}
		
		if(!checkG()) {
			if(DEBUG) {
				System.out.println("g value is NOT valid.");
			}
			
			flag = false;
		} else {
			if(DEBUG) {
				System.out.println("g value is valid.");
			}
		}
		
		if(!checkKeypair()) {
			if(DEBUG) {
				System.out.println("Keypair is NOT valid.");
			}
			
			flag = false;
		} else {
			if(DEBUG) {
				System.out.println("Keypair is valid.");
			}
		}
		
		return flag;
	}

	// hashes the message
	private static BigInteger hashMsg(String m) throws Exception {
		MessageDigest sha = MessageDigest.getInstance("SHA1");
        sha.update(m.getBytes()); // get the hash
		return new BigInteger(1, sha.digest());
	}
	
	/// the next few functions just individually check the system parameters and other values ///
	
	private static boolean checkP() {
		int bits = p.bitLength();
		return bits % 64 == 0 && bits >= 512 && bits <= 1024;
	}
	
	private static boolean checkQ() {
		return p.subtract(BigInteger.ONE).mod(q).compareTo(BigInteger.ZERO) == 0 && q.bitLength() == 160;
	}
	
	private static boolean checkG() {
		return g.modPow(q, p).compareTo(BigInteger.ONE) == 0;
	}
	
	private static boolean checkKeypair() {
		return g.modPow(skCA, p).compareTo(pkCA) == 0;
	}
	
	/// end checking ///
	
	public static String getExpiry() {
		return expiryDate;
	}
	
	public static void setExpiry(String expiry) {
		expiryDate = expiry;
		
		if(DEBUG) {
			System.out.println("Expiry set to: " + expiryDate);
		}
	}
}
