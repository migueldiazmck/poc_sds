import { parse, format } from 'date-fns';
import {Cipher, createCipheriv, createDecipheriv, createDecipher, createCipher, createSecretKey, createHash, Hex, pbkdf2, randomBytes, pbkdf2Sync } from 'crypto';

const DeviceIdPhone = "ece4124e31e6212b";
const password = "9876";
const IdentSerialNum = "1033240004";
const BankId = "0097";
const ClientDt = "2020-07-30T11:23:16.573";

function encryptSHA512(input: string): string {
  let target = '';
  const pattern = /[a-zA-Z0-9]+/g;
  const matches = input.match(pattern);
  if (matches) {
    target = matches.join('');
  }

  try {
    const hash = createHash('sha512');
    hash.update(target);
    const digestHash = hash.digest();
    let out = '';
    for (const i of digestHash) {
      let s = i.toString(16);
      while (s.length < 2) {
        s = `0${s}`;
      }
      out += s;
    }
    return out;
  } catch (e) {
    console.error(e);
  }
  return '';
}

const getLast8 = (data: string) => {
  if (data.length > 7) {
    return data.substring(data.length - 8, data.length);
  }
  return null;
};

function main() {
  const iv = "F27D5C9927726BCEFE7510B1BDD3D137";
	const salt = "3FF2EC019C627B945225DEBAD71A01B6985FE84C95A70EB132882F88C0A59A55";

  const date = parse(ClientDt, "yyyy-MM-dd'T'HH:mm:ss.SSS", new Date());
  const DeviceHour = format(date, "SSSssmmHH");
  const passprhase = getLast8(encryptSHA512(DeviceIdPhone)) + IdentSerialNum + BankId + DeviceHour;
  const javaPassprase = '477325e310332400040097573162311';
  console.log(passprhase);
  console.log(passprhase === javaPassprase);
  const encrypt = encrypted({ iv, salt, passprhase, password });
  const aespassword = encrypt.toString('base64');
  console.log(aespassword);
  const javaAespassword = 'iKerBmOWlwvfvkyJQm7RxQ==';
  console.log(javaAespassword === aespassword);
}

function encrypted({ iv, salt, passprhase, password}): Buffer  {
  const keySize = 256;
  const iterationCount = 10;
  const saltBuffer = Buffer.from(salt, 'hex');
  const secretKey = pbkdf2Sync(Buffer.from(passprhase), saltBuffer, iterationCount, keySize / 8, 'sha1');
  const cipher = createCipheriv('aes-256-cbc', secretKey, Buffer.from(iv, 'hex'));
  cipher.update(Buffer.from(password, 'utf8'));
  return cipher.final();
}

main();

