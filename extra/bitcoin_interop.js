var openpgp = require('openpgp');
var bitcoin = require('bitcoinjs-lib');
var bs58check = require('bs58check');
var crypto = require('crypto');
var chai = require('chai'),
    expect = chai.expect;

describe('Bitcoin OpenPGP interop', function () {
  it('Generate openpgp key from bitcoin key', function (done) {
    // bitcoin
    var bitcoin_key = bitcoin.ECPair.makeRandom();
    var wif = bitcoin_key.toWIF();

    // openpgp
    var buff = bs58check.decode(wif);
    expect(buff.length).to.equal(34);

    var pk = buff.slice(1, -1);
    var material = openpgp.util.bin2str(pk);
    var options = {
      userIds {name: "userid", email: "none@example.net"},
      curve: "secp256k1",
      material: {
        key: material,
        subkey: material
      }
    };
    openpgp.generateKey(options).then(function (openpgp_key) {
      expect(openpgp_key).to.exist;
      expect(openpgp_key.key).to.exist;
      expect(openpgp_key.key.primaryKey).to.exist;
      expect(openpgp_key.key.primaryKey.mpi[2].toBytes()).to.equal(material);
      done();
    });
  });
  it('Generate openpgp key from bitcoin HDKey', function (done) {
    // bitcoin
    var seed = crypto.randomBytes(32);
    var master = bitcoin.HDNode.fromSeedBuffer(seed);
    var child = master.derive(42);
    var s = child.toBase58();

    // openpgp
    var buff = bs58check.decode(s);
    expect(buff.length).to.equal(78);
    var chain = buff.slice(13, 45);
    var pk = buff.slice(46, 78);

    var buff = openpgp.util.bin2str(pk);
    var options = {
      userIds: {name: "userid", email: "none@example.net"},
      curve: "secp256k1",
      material: {
        key: buff,
        subkey: buff
      }
    };
    openpgp.generateKey(options).then(function (openpgp_key) {
      expect(openpgp_key).to.exist;
      expect(openpgp_key.key).to.exist;
      expect(openpgp_key.key.primaryKey).to.exist;
      expect(openpgp_key.key.primaryKey.mpi[2].toBytes()).to.equal(buff);
      done();
    });
  });
});

