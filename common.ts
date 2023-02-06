import { createHash, pbkdf2Sync, createSecretKey } from 'crypto';
import * as crypto from 'crypto';
import { createCipheriv, createDecipheriv, randomBytes, scrypt } from 'crypto';
import { promisify } from 'util';

export const setHeaders = (username: string, config, clientId: string) => {
  return {
    ...config.headers,
    'X-RqUID': Math.floor(1000 + Math.random() * 9000),
    'X-Channel': 'MB',
    'X-CompanyId': '0097',
    'X-IdentSerialNum': username,
    'X-GovIssueIdentType': 'CC',
    'X-IPAddr': '180.210.239.124',
    'X-Language': 'ES_CO',
    'X-Name': 'SM-A505G',
    'X-NextDt': '1998-07-05T02:46:01.727Z',
    'X-Sesskey': '353556088920453',
    'X-Version': '1.8',
    'X-Org': 'aval',
    'X-Reverse': 'false',
    'X-LastName': 'PRUEBA  SWITCH AHO25.',
    'X-CustIdentType': 'CC',
    'X-CustIdentNum': username,
    'X-LegalName': 'PRUEBA  SWITCH AHO25.',
    'Content-Type': 'application/json',
    Accept: 'application/json',
    'X-IBM-Client-Id': clientId,
    'apim-debug': 'true',
    'X-ClientDt': '2020-07-30T11:23:16.573',
  };
};

export const setBody = (deviceId: string, password: string) => {
  return {
    BankInfo: {
      RefInfo: {
        RefType: 'CLAVE_UNIVERSAL',
        RefId: 'SI',
      },
    },
    SecretList: {
      SecretId: 'password',
      Secret: password,
      SecObjId: deviceId,
    },
    ClientApp: {
      Org: 'aval',
      Name: 'MB',
      Version: '1.8',
    },
  };
};

const getLast8 = (data: string) => {
  if (data.length > 7) {
    return data.substring(data.length - 8, data.length);
  }
  return null;
};

export const aesEncription = () => {
  const iv = 'F27D5C9927726BCEFE7510B1BDD3D137';
  const salt =
    '3FF2EC019C627B945225DEBAD71A01B6985FE84C95A70EB132882F88C0A59A55';
  const date = new Date();
  const deviceHour =
    date.getMilliseconds() +
    '' +
    date.getSeconds() +
    '' +
    date.getMinutes() +
    '' +
    date.getHours();
  const passphrase =
    getLast8(encryptSHA512('ece4124e31e6212b')) +
    '807509975' +
    '0097' +
    deviceHour;

  const key = generateKey(salt, passphrase);
  console.log('key ' + key);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key), iv);
  console.log('cipher-->', cipher);

  // const value = cipher.final();

  // const test = value.toString("utf-8");

  // console.log(test);

  // SecretKey key = generateKey(salt, passphrase);
  // byte[] encrypted = doFinal(1, key, iv, password.getBytes("UTF-8"));
  // //System.out.println("AES passphrase: "+passphrase);
  // System.out.println("AES password: "+Base64.encodeBase64String(encrypted));
};

export function encryptSHA512(input: string): string | null {
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
  return null;
}

export function generateKey(salt: string, passphrase: string): Buffer | null {
  try {
    const keySize = 256;
    const iterationCount = 10;
    //  const derivedKey = pbkdf2Sync(
    //    passphrase,
    //    Buffer.from(salt, 'hex'),
    //    iterationCount,
    //    keySize,
    //    iterationCount,
    //    'sha1',
    // );
    // return derivedKey;
    const bufferKey = crypto.pbkdf2Sync(
      passphrase,
      Buffer.from(salt, 'hex'),
      keySize,
      iterationCount,
      'sha1',
    );
    return bufferKey;
  } catch (e) {
    console.error(e);
  }
  return null;
}
