const assert = require('assert');

const BigNumber = require('bignumber.js');
const { Point } = require('./Point');
const { FQ } = require('./Field');

//for buffer reserse
const reverse = require("buffer-reverse");

//TODO : Should check whether this library's random is cryptographically safe
var crypto = require('crypto');

class PrivateKey {
  constructor(sk = ""){
    if(sk instanceof PrivateKey){
      this.s = sk.s;
    }
    this.s = new FQ(sk);
  }

  static getRandObj(len=32){
    let randomHex = PrivateKey._randomValueHex(len);
    let bf = Buffer.from(randomHex, 'hex');
    let littleEndianRandom = "0x" + reverse(bf).toString('hex');
    // let bigEndianRandom = "0x" + bf.toString('hex');
    // console.log('randomHex : ', randomHex, randomHex.length);
    // console.log('littleEndian :', littleEndianRandom);
    let bn = new BigNumber(littleEndianRandom);
    return {
      field : new FQ(bn),
      hexString : randomHex
    }
  }

  static _randomValueHex(len=32) {
    return crypto
      .randomBytes(Math.ceil(len / 2))
      .toString('hex') // convert to hexadecimal format
      .slice(0, len); // return required number of characters
  }

}

class PublicKey {
  constructor(pubkey=null) {
    //TODO : if pubkey.p == null, this.p == null
    if(pubkey instanceof PublicKey){
      this.p = pubkey.p;
    } else if(pubkey instanceof Point){
      this.p = pubkey;
      // console.log(this.p);
    } else if(pubkey == null){
      this.p = pubkey;
    } else {
      assert(false, 'pubkey should be PublicKey or Point');
    }
  }

  importPrivate(sk) {
    let generator = Point.generator();
    if(!(sk instanceof PrivateKey)){
      sk = new PrivateKey(sk);
    }
    this.p = generator.mult(sk.s);
    return this;
  }

  static fromPrivate(sk) {
    let generator = Point.generator();
    if(!(sk instanceof PrivateKey)){
      sk = new PrivateKey(sk);
    }
    let A = generator.mult(sk.s);
    return new PublicKey(A);
  }

  verifySk(sk){
    assert(this.p != null, "publicKey should be initialized");
    let generator = Point.generator();
    if(!(sk instanceof PrivateKey)){
      sk = new PrivateKey(sk);
    }
    return this.p.isEqualTo(generator.mult(sk.s));
  }
}

class Jub {
  static encrypt(message, privateKey, random){
    return
  }

  static decrypt(encrypted, privateKey){
    assert(encrypted.constructor === Array);
    let originVector = [];
    let k;

    if(privateKey instanceof PrivateKey){
      k = privateKey.s;
    } else {
      k = new FQ(privateKey);
    }

    for(let i=0; i<encrypted.length; i++){
      let c1;
      let c2;
      let decrypted;
      let originX;
      c1 = new Point(encrypted[i]["c1"].x, encrypted[i]["c1"].y);
      c2 = new Point(encrypted[i]["c2"].x, encrypted[i]["c2"].y);
      decrypted = c1.add(c2.mult(k).neg()); // M = C1 - k*C2
      originX = decrypted.x.sub(new FQ(encrypted[i]["added"]));
      //console.log(originX);
      originVector.push(originX.n.toFixed());
    }

    return originVector;
  }

  static encrypt(vector, publicKey, random){
    assert(vector.constructor === Array);
    assert(publicKey instanceof PublicKey);

    let K = publicKey.p; // for public key
    let r; // for random number
    let G = Point.generator(); // for Generator
    let cipher = []; // for cipher

    if(random instanceof FQ){
      r = random;
    } else {
      r = new FQ(random);
    }

    let points = Jub._vectorToAddedPoint(vector);

    for(let pKey in points){
      let c = {"c1": "", "c2" : "", "added" : ""};
      let rawM = points[pKey][0];
      let rawAdded = points[pKey][1];
      let M = new Point(rawM.x, rawM.y);
      let c1Raw = M.add(K.mult(r));
      let c2Raw = G.mult(r);

      c["c1"] = {"x" : c1Raw.x.n.toFixed(), "y" : c1Raw.y.n.toFixed()};
      c["c2"] = {"x" : c2Raw.x.n.toFixed(), "y" : c2Raw.y.n.toFixed()};
      c["added"] = rawAdded["added"];
      cipher.push(c);
    }

    return cipher;
  }

  static _vectorToAddedPoint(vector){
    assert(vector.constructor === Array);
    let pointObj = {};
    for(let i=0; i < vector.length; i++){
      let value = vector[i];
      let key = "p"+i;
      let point = Point.fieldToPoint(value);
      let formattedCipher = [
        {
          "x" : point.point.x.n.toFixed(),
          "y" : point.point.y.n.toFixed()
        },{
          "added" : point.added.toFixed()
        }
      ];
      pointObj[key] = formattedCipher;
    }
    return pointObj;
  }
}

module.exports = {
  PrivateKey,
  PublicKey,
  Jub,
}

//function test(){
//  let vector1 = [1,2,3,4,5,6,7,8,9,10];
//  let vector2 = [1]
//  let vector3 = [91]
//  //console.log(Jub._vectorToAddedPoint(vector));
//  let pubkey = PublicKey.fromPrivate("19611251047126512");
//  //console.log(pubkey);
//  let encrypted = Jub.encrypt(vector1, pubkey, "12312412524")
//  console.log(encrypted);
//  console.log("");
//  console.log(Jub.decrypt(encrypted, "19611251047126512"));
//}

//test()
