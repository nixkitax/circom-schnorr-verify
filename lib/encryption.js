//TODO : Does not work

const BigNumber = require('bignumber.js');

const { PrivateKey, PublicKey } = require('./KeyGenerator.js');
const { Point } = require('./Point.js');
const { FQ, FR } = require('./Field.js');


const GROUP_SIZE = 15; //Length[IntegerDigit[p, 65536]] - 1, for ASCII

function chunk(array, size) {
    const chunked_arr = [];
    for (let i = 0; i < array.length; i++) {
      const last = chunked_arr[chunked_arr.length - 1];
      if (!last || last.length === size) {
        chunked_arr.push([array[i]]);
      } else {
        last.push(array[i]);
      }
    }
    return chunked_arr;
}

function messageToArrayGroup(message, group_size=GROUP_SIZE){
  var arrayM = message.split('');
  var chunkedMessage = chunk(arrayM, 15);
  var hexedChunk = chunkedMessage.map(x => x.map(y => y.charCodeAt(0).toString(16)));
  var bigIntChunk = hexedChunk.map(x => new BigNumber("0x"+x.join('')));

  if(bigIntChunk.length % 2 != 0){
    bigIntChunk = bigIntChunk.concat(new BigNumber("32"));
  }

  return bigIntChunk;
}

var message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean vehicula, ligula in eleifend consequat, mi dui aliquam felis, eget mollis tortor nunc pretium ex. Duis eros nulla, consectetur et velit a, gravida lacinia tellus. Fusce venenatis dui in orci lobortis, nec feugiat est pretium. Fusce nisi dolor, lacinia a felis eu, eleifend lacinia ante. Nunc consectetur ipsum ut sapien dignissim, id gravida mauris tristique. Praesent egestas bibendum ultrices. Curabitur quam sem, finibus luctus erat nec, feugiat tempor sem. Proin maximus placerat felis. Cras nec lacus libero. Etiam malesuada eu sem a tincidunt. Quisque eget sapien nec nunc malesuada finibus. Nunc vitae tortor fringilla, blandit nisl sed, elementum diam.";


function test(){

  // K = k*G (pubKey: K, signKey : k, generator : G)

  // Encryption
  //1. C1 = M + r*K
  //2. C2 = r*G

  // Decryption
  // 3. M = C1 - k*C2

  //why?
  // -> C1 = M + r*K
  // -> M = C1 - r*K --> It fails?
  // -> M = C1 - r*k*G
  // -> M = C1 - k*C2

  //encryption

  // let arrayG = messageToArrayGroup(message);
  // console.log(arrayG);
  let M = new Point("12576558175125128246374296641007938322302911659474853157208587689687229831284", 3);
  console.log("M.x : ", M.x.n.toFixed()); // No Problem
  console.log("M.y : ", M.y.n.toFixed()); // No Problem
  console.log("");

  // let M = new Point(PrivateKey.getRandObj().field, PrivateKey.getRandObj().field);
  let G = Point.generator();
  // console.log("G.x : ",G.x.n.toFixed()); // No Problem
  // console.log("G.y : ",G.y.n.toFixed()); // No Problem

  // let kString = '1997011358982923168928344992199991480689546837621580239342656433234255379025';
  let kString = '199';
  let k = new FQ(kString);
  console.log("k(private key) : ",k.n.toFixed()); // No Problem
  let K = G.mult(k); //K = k*G
  console.log("K.x(public key) : ", K.x.n.toFixed()); // No Problem
  console.log("K.y(public key) : ", K.y.n.toFixed()); // No Problem

  // let r = PrivateKey.getRandObj().field;
  // let r =new FQ('16540640123574156134436876038791482806971768689494387082833631921987005038934');
  let r =new FQ('165');
  console.log("r(random number) : ", r.n.toFixed());

  let C1 = M.add(K.mult(r)); //C1 = M + r*K //No Problem
  let C2 = G.mult(r); //C2 = r*G

  console.log("C1.x : ",C1.x.n.toFixed()); //No Problem
  console.log("C1.y : ",C1.y.n.toFixed()); //No Problem
  //
  // console.log("C1.neg().x : ",C1.neg().x.n.toFixed()); //No Problem
  // console.log("C1.neg().y : ",C1.neg().y.n.toFixed()); //No Problem

  //decryption

  let decM = C1.add(C2.mult(k).neg()); // M = C1 - k*C2

  // console.log("C2.neg().x : ", C2.neg().x.n.toFixed());
  // console.log("C2.neg().y : ", C2.neg().y.n.toFixed());
  console.log("C2.x       : ", C2.x.n.toFixed());
  console.log("C2.y       : ", C2.y.n.toFixed());

  //check
  console.log("");
  console.log("decM.x : ", decM.x.n.toFixed());
  console.log("decM.y : ", decM.y.n.toFixed());

  console.log("M.x    : ", M.x.n.toFixed());
  console.log("M.y    : ", M.y.n.toFixed());

  // console.log("pMkpB : ", pMkpB.x.n.toFixed());





  // //scalars test
  //
  // //(r*k)*G == r*(k*G)?
  // console.log("\n(r*k)*G == r*(k*G)? ")
  // console.log("G*(r*k).x : ", G.mult(r.mul(k)).x.n.toFixed());
  // console.log("(G*r)*k).x : ", G.mult(r).mult(k).x.n.toFixed());
  // console.log("(G*k)*r).x : ", G.mult(k).mult(r).x.n.toFixed());
  //
  // // C1 = M + r*K ?
  // console.log("\nC1 = M + r*K ? ")
  // console.log("C1.x        : ", C1.x.n.toFixed()); //No Problem
  // console.log("C1.y        : ", C1.y.n.toFixed()); //No Problem
  // console.log("(M + K*r).x : ", M.add(K.mult(r)).x.n.toFixed());
  // console.log("(M + K*r).y : ", M.add(K.mult(r)).y.n.toFixed());
  //
  // //M = C1 - r*K ?
  // //Something Wrong
  // console.log("\nM = C1 - r*K ?")
  // console.log("M.x      : ", M.x.n.toFixed());
  // console.log("M.y      : ", M.y.n.toFixed());
  // console.log("C1 - r*K : ", C1.add( K.mult(r).neg() ).x.n.toFixed());
  // console.log("C1 - r*K : ", C1.add( K.mult(r).neg() ).y.n.toFixed());
  //
  // // M + C1 - C1 == M ?
  // console.log("\nM + C1 - C1 == M ?")
  // console.log("M.x       : ", M.x.n.toFixed());
  // console.log("M.y       : ", M.y.n.toFixed());
  // console.log("(M+C1)-C1 : ", M.add(C1).add(C1.neg()).x.n.toFixed());
  // console.log("(M+C1)-C1 : ", M.add(C1).add(C1.neg()).y.n.toFixed());
  // console.log("M+(C1-C1) : ", M.add( C1.add(C1.neg()) ).x.n.toFixed());
  // console.log("M+(C1-C1) : ", M.add( C1.add(C1.neg()) ).y.n.toFixed());


}

test();
