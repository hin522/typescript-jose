import { JWK, JWE, JWS } from "node-jose";
import { S3Service } from "./s3Service";

const A128CBC_HS256 = "A128CBC-HS256";
const ECDH_ES = "ECDH-ES";
const ES384 = "ES384";

const CLIENT_PRIVATE_KEY_CODE: string = "CLIENT_PRIVATE_KEY_CODE";
const SERVER_PUBLIC_KEY_CODE: string = "SERVER_PUBLIC_KEY_CODE";

export class JoseService {
  private keyRegistry = new Map<string, any>();
  private s3: S3Service;

  constructor(s3: S3Service) {
    this.s3 = s3;
  }

  public async setupKeys() {
    const clientPrivateKey = await this.s3.getObject("<JOSE_KEYS_BUCKET>", "<PRIVATE_KEY_S3_PATH>");
    const serverPublicKey = await this.s3.getObject("<JOSE_KEYS_BUCKET", "<PUBLIC_KEY_S3_PATH>");
    await this.registerKey(CLIENT_PRIVATE_KEY_CODE, clientPrivateKey, "pem");
    await this.registerKey(SERVER_PUBLIC_KEY_CODE, serverPublicKey, "pem");
  }

  public async signOnly(): Promise<string> {
    const claims = {
      iss: "SOME_IDENTITY",
      aud: "SOME_IDENTITY",
      iat: new Date().getTime()
    };

    const claimsStr = JSON.stringify(claims);
    const signed = await this.signToJws(claimsStr);
    return signed;
  }

  public async verifyJws(theJws: string): Promise<{ payload: Buffer }> {
    if (!theJws) { throw new Error("Missing jws to verify."); }

    const jwkPublicKey = this.keyRegistry.get(SERVER_PUBLIC_KEY_CODE);
    const opts = {
      algorithms: [ES384]
    };
    const verified = await JWS
      .createVerify(jwkPublicKey, opts)
      .verify(theJws);
    return verified;
  }

  public async signAndEncrypt(dataObj: object): Promise<string> {
    if (!dataObj) { throw new Error("Missing raw data object to sign and encrypt."); }

    const claims = {
      iss: "SOME_IDENTITY",
      aud: "SOME_IDENTITY",
      iat: new Date().getTime(),
      data: dataObj
    };

    const claimsStr = JSON.stringify(claims);
    const signed = await this.signToJws(claimsStr);
    const encrypted = await this.encryptToJwe(signed);
    console.log("Created JWE for the payload");
    return encrypted;
  }

  public async decryptAndVerify<T>(encryptedAndSignedStr: string): Promise<T> {
    if (!encryptedAndSignedStr) { throw new Error("Missing string data to decrypt and verify."); }

    const decrypted = await this.decryptJwe(encryptedAndSignedStr);
    const decryptedPayloadStr = decrypted.payload.toString();
    const verified = await this.verifyJws(decryptedPayloadStr);
    const parsedPayload: T = JSON.parse(verified.payload.toString());
    console.log("Decrypted and verified response");
    return parsedPayload;
  }

  public async decryptJwe(theJwe: string): Promise<{ payload: Buffer }> {
    if (!theJwe) { throw new Error("Missing JWE string to decrypt."); }

    const jwkPrivateKey = this.keyRegistry.get(CLIENT_PRIVATE_KEY_CODE);
    const opts = {
      algorithms: [ECDH_ES, A128CBC_HS256]
    };
    const decrypted = await JWE
      .createDecrypt(jwkPrivateKey, opts)
      .decrypt(theJwe);
    return decrypted;
  }

  private async encryptToJwe(data: string): Promise<string> {
    if (!data) { throw new Error("Missing raw data object to encrypt."); }

    const jwkPublicKey = this.keyRegistry.get(SERVER_PUBLIC_KEY_CODE);
    const buffer = Buffer.from(data);
    const encrypted = await JWE
      .createEncrypt({
        format: "compact",
        contentAlg: A128CBC_HS256,
        fields: {
          alg: ECDH_ES,
          cty: "JWT"
        }
      }, jwkPublicKey)
      .update(buffer)
      .final();
    return encrypted;
  }

  private async signToJws(data: string): Promise<string> {
    if (!data) { throw new Error("Missing raw data object to sign."); }

    const jwkPrivateKey = this.keyRegistry.get(CLIENT_PRIVATE_KEY_CODE);
    const buffer = Buffer.from(data);
    const signed = await JWS
      .createSign({ format: "compact", alg: ES384 }, jwkPrivateKey).
      update(buffer).
      final();
    return signed;
  }

  private async registerKey(keyCode: string, theKey: string, format: string) {
    console.log("Registering key: ", keyCode);
    const jwkKey = await JWK.asKey(theKey, format);
    this.keyRegistry.set(keyCode, jwkKey);
  }
}
