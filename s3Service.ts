import AWS = require("aws-sdk");

export class S3Service {
  private s3: AWS.S3;

  constructor() {
    this.s3 = new AWS.S3({signatureVersion: "v4"});
  }

  public getObject = async (bucket: string, key: string): Promise<any> => {
    return new Promise<any>((resolve, reject) => {
      this.s3.getObject({Bucket: bucket, Key: key}, (err, data) => {
        if (err) {
          console.error(`>> S3 getObject at ${bucket}/${key} failed `, err);
          reject(err);
        } else {
          resolve(data.Body);
        }
      });
    });
  }
}
