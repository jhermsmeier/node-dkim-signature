interface SignatureOptions {
  algorithm: string;
  canonical: string;
  copiedHeaders: string;
  domain: string;
  expires: string;
  hash: string;
  headers: string;
  identity: string;
  length: string;
  query: string;
  selector: string;
  signature: string;
  timestamp: string;
  version: string;
}

declare class Signature {

  algorithm: string;
  canonical: string;
  copiedHeaders: string;
  domain: string;
  expires: string;
  hash: string;
  headers: string;
  identity: string;
  length: string;
  query: string;
  selector: string;
  signature: string;
  timestamp: string;
  version: string;

  constructor(options: Partial<SignatureOptions>);

  static create(options: SignatureOptions): Signature;

  static fieldMap: {
    a: string;
    b: string;
    bh: string;
    c: string;
    d: string;
    h: string;
    i: string;
    l: string;
    q: string;
    s: string;
    t: string;
    v: string;
    x: string;
    z: string;
  };

  static fields: string[];

  static keys: string[];

  static parse(dkimHeader: any): Signature;

  parse(input: string): Signature;

  toString(): string;

}

export = Signature;
