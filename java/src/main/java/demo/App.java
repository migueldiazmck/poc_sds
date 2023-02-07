package demo;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

public class App {
	public static void main(String[] args) throws DatatypeConfigurationException, ParseException {
		System.out.println("Hello");

		String password = "9876";

		String IdentSerialNum = "1033240004";
		String BankId = "0097";
		String ClientDt = "2020-07-30T11:23:16.573";
		//String DeviceIdPhone = "version%3D3%2E4%2E1%2E0%5F1%26pm%5Ffpua%3Dmozilla%2F5%2E0%20%28windows%20nt%206%2E1%29%20applewebkit%2F537%2E36%20%28khtml%2C%20like%20gecko%29%20chrome%2F80%2E0%2E3987%2E149%20safari%2F537%2E36%7C5%2E0%20%28Windows%20NT%206%2E1%29%20AppleWebKit%2F537%2E36%20%28KHTML%2C%20like%20Gecko%29%20Chrome%2F80%2E0%2E3987%2E149%20Safari%2F537%2E36%7CWin32%26pm%5Ffpsc%3D24%7C1360%7C768%7C728%26pm%5Ffpsw%3D%26pm%5Ffptz%3D%2D5%26pm%5Ffpln%3Dlang%3Des%2DES%7Csyslang%3D%7Cuserlang%3D%26pm%5Ffpjv%3D0%26pm%5Ffpco%3D1%26pm%5Ffpasw%3Dinternal%2Dpdf%2Dviewer%7Cmhjfbmdgcfjbbpaeojofohoefgiehjai%7Cinternal%2Dnacl%2Dplugin%26pm%5Ffpan%3DNetscape%26pm%5Ffpacn%3DMozilla%26pm%5Ffpol%3Dtrue%26pm%5Ffposp%3D%26pm%5Ffpup%3D%26pm%5Ffpsaw%3D1360%26pm%5Ffpspd%3D24%26pm%5Ffpsbd%3D%26pm%5Ffpsdx%3D%26pm%5Ffpsdy%3D%26pm%5Ffpslx%3D%26pm%5Ffpsly%3D%26pm%5Ffpsfse%3D%26pm%5Ffpsui%3D%26pm%5Fos%3DWindows%26pm%5Fbrmjv%3D80%26pm%5Fbr%3DChrome%26pm%5Finpt%3D%26pm%5Fexpt%3D";
		String DeviceIdPhone = "ece4124e31e6212b";


		encriptarAES(IdentSerialNum, DeviceIdPhone, BankId, ClientDt, password);
	}

	private static void encriptarAES(String IdentSerialNum, String DeviceIdPhone, String BankId, String ClientDt, String password) throws DatatypeConfigurationException, ParseException{
		try
		{
			String iv = "F27D5C9927726BCEFE7510B1BDD3D137";
			String salt = "3FF2EC019C627B945225DEBAD71A01B6985FE84C95A70EB132882F88C0A59A55";

			GregorianCalendar cal = new GregorianCalendar();
			String format = "yyyy-MM-dd'T'HH:mm:ss.SSS";
			cal.setTime(new SimpleDateFormat(format).parse(ClientDt));
			XMLGregorianCalendar fecha = DatatypeFactory.newInstance().newXMLGregorianCalendar(cal);
			Calendar calendar = fecha.toGregorianCalendar();
			SimpleDateFormat formatter = new SimpleDateFormat("SSSssmmHH");
			formatter.setTimeZone(calendar.getTimeZone());
			String DeviceHour = formatter.format(calendar.getTime());
			//DeviceHour = "077303202";
			String passphrase =  getLast8(encryptSHA512(DeviceIdPhone)) + IdentSerialNum + BankId + DeviceHour;
			SecretKey key =  generateKey(salt, passphrase);
			byte[] encrypted = doFinal(1, key, iv, password.getBytes("UTF-8"));

			System.out.println("AES passphrase: "+passphrase);
			System.out.println("AES password: "+ Base64.encodeBase64String(encrypted));
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}
	}

	private static byte[] doFinal(int encryptMode, SecretKey key, String iv, byte[] bytes)
			throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
	{
		try

		{

			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(encryptMode, key, new IvParameterSpec(hex(iv)));
			return cipher.doFinal(bytes);
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}
		return null;
	}

	private static String getLast8(String data)
	{
		if (data.length() > 7) {
			return data.substring(data.length() - 8, data.length());
		}
		System.out.println("El dato recibido no contiene 8 digitos");
		return null;
	}

	public static byte[] hex(String str)
	{
		try
		{
			return Hex.decodeHex(str.toCharArray());
		}
		catch (DecoderException e)
		{
			e.printStackTrace();
		}
		return null;
	}

	private static SecretKey generateKey(String salt, String passphrase)
	{
		try
		{
			int keySize = 256;
			int iterationCount = 10;
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
			KeySpec spec = new PBEKeySpec(passphrase.toCharArray(), hex(salt), iterationCount, keySize);
			return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
		}
		catch (NoSuchAlgorithmException e)
		{
			e.printStackTrace();
		}
		catch (InvalidKeySpecException e)
		{
			e.printStackTrace();
		}
		return null;
	}

	public static final String encryptSHA512(String target)
	{
		String test = "";
		Pattern pattern = Pattern.compile("[a-zA-Z0-9]+");
		Matcher matcher = pattern.matcher(target);
		while (matcher.find()) {
			test = test + matcher.group().replaceAll(",", "");
		}
		target = test;
		try
		{
			MessageDigest md = MessageDigest.getInstance("SHA-512");

			md.update(target.getBytes());
			byte[] mb = md.digest();
			String out = "";
			for (int i = 0; i < mb.length; i++)
			{
				byte temp = mb[i];
				String s = Integer.toHexString(new Byte(temp).byteValue());
				while (s.length() < 2) {
					s = "0" + s;
				}
				s = s.substring(s.length() - 2);
				out = out + s;
			}
			return out;
		}
		catch (NoSuchAlgorithmException e)
		{
			e.getStackTrace();
		}
		return null;
	}
}