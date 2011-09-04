/****************************************
 *
 * DSS-Based Mini-Certificate Generation
 * Certificate Code
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

public class Cert { 
	// for debugging
	private static final boolean DEBUG = false;
	private static String m;
	private static BigInteger r;
	private static BigInteger s;
	
	// constructor
	public Cert(String message, BigInteger rVal, BigInteger sVal) {
		m = message;
		r = rVal;
		s = sVal;
	}
	
	/// just some getters and setters ///
	
	public static String getM() {
		return m;
	}
	
	public static BigInteger getR() {
		return r;
	}
	
	public static BigInteger getS() {
		return s;
	}
	
	public static void setM(String message) {
		m = message;
	}
	
	public static void setR(BigInteger rVal) {
		r = rVal;
	}
	
	public static void setM(BigInteger sVal) {
		s = sVal;
	}
}
