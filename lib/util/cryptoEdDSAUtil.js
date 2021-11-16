const crypto = require('crypto');
const elliptic = require('elliptic');
const EdDSA = elliptic.eddsa;
const ec = new EdDSA('ed25519');
const cryptoe = require("crypto-extra")



/* function makeid(length) {
    var result           = '';
    var characters       = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    var charactersLength = characters.length;
    for ( var i = 0; i < length; i++ ) {
      result += characters.charAt(Math.floor(Math.random() * 
 charactersLength));
   }
   return result;
}

-- old salt generation not cryptographically secure. 

*/ 

const SALT = cryptoe.randomString(1000);

class CryptoEdDSAUtil {
    static generateSecret(password) {
        let secret = crypto.pbkdf2Sync(password, SALT, 10000, 512, 'sha512').toString('hex');
        console.debug(`Secret: \n${secret}`);
        return secret;
    }

    static generateKeyPairFromSecret(secret) {
        // Create key pair from secret
        let keyPair = ec.keyFromSecret(secret); // hex string, array or Buffer        
        console.debug(`Public key: \n${elliptic.utils.toHex(keyPair.getPublic())}`);
        return keyPair;
    }

    static signHash(keyPair, messageHash) {
        let signature = keyPair.sign(messageHash).toHex().toLowerCase();
        console.debug(`Signature: \n${signature}`);
        return signature;
    }

    static verifySignature(publicKey, signature, messageHash) {
        let key = ec.keyFromPublic(publicKey, 'hex');
        let verified = key.verify(messageHash, signature);
        console.debug(`Verified: ${verified}`);
        return verified;
    }

    static toHex(data) {
        return elliptic.utils.toHex(data);
    }
}

module.exports = CryptoEdDSAUtil;
