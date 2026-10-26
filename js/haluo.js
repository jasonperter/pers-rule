const STATIC_KEY = "0199bec97dfa5e0d";
const KEY_CACHE = "HBE_LiteAES_Key_v1";
const MAX_SIZE = 3 * 1024 * 1024;

/* ========== 存储 ========== */
function sGet(k) {
  try {
    if (typeof $persistentStore !== "undefined" && $persistentStore)
      return $persistentStore.read(k);
    if (typeof $prefs !== "undefined" && $prefs)
      return $prefs.valueForKey(k);
  } catch (e) {}
  return null;
}
function sSet(k, v) {
  try {
    if (typeof $persistentStore !== "undefined" && $persistentStore)
      return $persistentStore.write(v, k);
    if (typeof $prefs !== "undefined" && $prefs)
      return $prefs.setValueForKey(v, k);
  } catch (e) {}
  return false;
}

/* ========== 精简 CryptoJS（仅 AES-CBC + Base64 + Utf8） ========== */
var CryptoJS = (function () {
  var C = {};
  var C_lib = (C.lib = {});
  var Base = (C_lib.Base = {
    extend: function (o) {
      var s = Object.create(this);
      if (o) for (var k in o) if (o.hasOwnProperty(k)) s[k] = o[k];
      if (!s.hasOwnProperty("init") || this.init === s.init)
        s.init = function () {
          s.$super.init.apply(this, arguments);
        };
      s.init.prototype = s;
      s.$super = this;
      return s;
    },
    create: function () {
      var i = this.extend();
      i.init.apply(i, arguments);
      return i;
    },
    init: function () {},
    mixIn: function (o) {
      for (var k in o) if (o.hasOwnProperty(k)) this[k] = o[k];
      if (o.hasOwnProperty("toString")) this.toString = o.toString;
    },
    clone: function () {
      return this.init.prototype.extend(this);
    }
  });

  var WordArray = (C_lib.WordArray = Base.extend({
    init: function (w, s) {
      w = this.words = w || [];
      this.sigBytes = s != null ? s : w.length * 4;
    },
    toString: function (e) {
      return (e || Hex).stringify(this);
    },
    concat: function (w) {
      var t = this.words,
        o = w.words,
        s = this.sigBytes,
        n = w.sigBytes;
      this.clamp();
      if (s % 4)
        for (var i = 0; i < n; i++)
          t[(s + i) >>> 2] |=
            ((o[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff) <<
            (24 - ((s + i) % 4) * 8);
      else for (var j = 0; j < n; j += 4) t[(s + j) >>> 2] = o[j >>> 2];
      this.sigBytes += n;
      return this;
    },
    clamp: function () {
      var w = this.words,
        s = this.sigBytes;
      w[s >>> 2] &= 0xffffffff << (32 - (s % 4) * 8);
      w.length = Math.ceil(s / 4);
    },
    clone: function () {
      var c = Base.clone.call(this);
      c.words = this.words.slice(0);
      return c;
    }
  }));

  var C_enc = (C.enc = {});
  var Hex = (C_enc.Hex = {
    stringify: function (wa) {
      var w = wa.words,
        s = wa.sigBytes,
        h = [];
      for (var i = 0; i < s; i++) {
        var b = (w[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
        h.push((b >>> 4).toString(16));
        h.push((b & 0xf).toString(16));
      }
      return h.join("");
    },
    parse: function (hex) {
      var l = hex.length,
        w = [];
      for (var i = 0; i < l; i += 2)
        w[i >>> 3] |= parseInt(hex.substr(i, 2), 16) << (24 - (i % 8) * 4);
      return new WordArray.init(w, l / 2);
    }
  });
  var Latin1 = (C_enc.Latin1 = {
    stringify: function (wa) {
      var w = wa.words,
        s = wa.sigBytes,
        c = [];
      for (var i = 0; i < s; i++)
        c.push(
          String.fromCharCode((w[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff)
        );
      return c.join("");
    },
    parse: function (str) {
      var l = str.length,
        w = [];
      for (var i = 0; i < l; i++)
        w[i >>> 2] |= (str.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8);
      return new WordArray.init(w, l);
    }
  });
  var Utf8 = (C_enc.Utf8 = {
    stringify: function (wa) {
      try {
        return decodeURIComponent(escape(Latin1.stringify(wa)));
      } catch (e) {
        throw new Error("Malformed UTF-8");
      }
    },
    parse: function (str) {
      return Latin1.parse(unescape(encodeURIComponent(str)));
    }
  });
  var Base64 = (C_enc.Base64 = {
    stringify: function (wa) {
      var w = wa.words,
        s = wa.sigBytes,
        map = this._map;
      wa.clamp();
      var a = [];
      for (var i = 0; i < s; i += 3) {
        var b1 = (w[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
        var b2 = (w[(i + 1) >>> 2] >>> (24 - ((i + 1) % 4) * 8)) & 0xff;
        var b3 = (w[(i + 2) >>> 2] >>> (24 - ((i + 2) % 4) * 8)) & 0xff;
        var t = (b1 << 16) | (b2 << 8) | b3;
        for (var j = 0; j < 4 && i + 0.75 * j < s; j++)
          a.push(map.charAt((t >>> (6 * (3 - j))) & 0x3f));
      }
      var p = map.charAt(64);
      if (p) while (a.length % 4) a.push(p);
      return a.join("");
    },
    parse: function (b64) {
      var l = b64.length,
        map = this._map,
        rev = this._reverseMap;
      if (!rev) {
        rev = this._reverseMap = [];
        for (var i = 0; i < map.length; i++) rev[map.charCodeAt(i)] = i;
      }
      var p = map.charAt(64);
      if (p) {
        var idx = b64.indexOf(p);
        if (idx !== -1) l = idx;
      }
      return (function (s, len, rev) {
        var w = [],
          n = 0,
          bits = 0;
        for (var i = 0; i < len; i++) {
          if (i % 4) {
            var c1 = rev[s.charCodeAt(i - 1)] << ((i % 4) * 2);
            var c2 = rev[s.charCodeAt(i)] >>> (6 - (i % 4) * 2);
            w[n >>> 2] |= (c1 | c2) << (24 - (n % 4) * 8);
            n++;
          }
        }
        return new WordArray.init(w, n);
      })(b64, l, rev);
    },
    _map: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
  });

  var BufferedBlockAlgorithm = (C_lib.BufferedBlockAlgorithm = Base.extend({
    reset: function () {
      this._data = new WordArray.init();
      this._nDataBytes = 0;
    },
    _append: function (d) {
      if (typeof d === "string") d = Utf8.parse(d);
      this._data.concat(d);
      this._nDataBytes += d.sigBytes;
    },
    _process: function (doFlush) {
      var data = this._data,
        words = data.words,
        sig = data.sigBytes,
        bs = this.blockSize,
        bsBytes = bs * 4,
        nBlocks = doFlush
          ? Math.ceil(sig / bsBytes)
          : Math.max((sig / bsBytes) | 0, 0);
      var nBytes = Math.min(nBlocks * bsBytes, sig);
      var processed;
      if (nBlocks) {
        for (var i = 0; i < nBlocks; i++) this._doProcessBlock(words, i * bs);
        processed = words.splice(0, nBlocks * bs);
        data.sigBytes -= nBytes;
      }
      return new WordArray.init(processed, nBytes);
    },
    clone: function () {
      var c = Base.clone.call(this);
      c._data = this._data.clone();
      return c;
    },
    _minBufferSize: 0
  }));

  var Hasher = (C_lib.Hasher = BufferedBlockAlgorithm.extend({
    cfg: Base.extend(),
    init: function (cfg) {
      this.cfg = this.cfg.extend(cfg);
      this.reset();
    },
    reset: function () {
      BufferedBlockAlgorithm.reset.call(this);
      this._doReset();
    },
    update: function (d) {
      this._append(d);
      this._process();
      return this;
    },
    finalize: function (d) {
      if (d) this._append(d);
      return this._doFinalize();
    },
    blockSize: 16,
    _createHelper: function (H) {
      return function (m, cfg) {
        return new H.init(cfg).finalize(m);
      };
    }
  }));

  var C_algo = (C.algo = {});

  // AES
  var SBOX = [],
    INV_SBOX = [],
    SUB_MIX = [[], [], [], []],
    INV_SUB_MIX = [[], [], [], []];
  (function () {
    var d = [];
    for (var i = 0; i < 256; i++) d[i] = i < 128 ? i << 1 : (i << 1) ^ 0x11b;
    var x = 0,
      xi = 0;
    for (var i = 0; i < 256; i++) {
      var sx = xi ^ (xi << 1) ^ (xi << 2) ^ (xi << 3) ^ (xi << 4);
      sx = (sx >>> 8) ^ (sx & 0xff) ^ 0x63;
      SBOX[x] = sx;
      INV_SBOX[sx] = x;
      var x2 = d[x],
        x4 = d[x2],
        x8 = d[x4];
      var t = (d[sx] * 0x101) ^ (sx * 0x1010100);
      SUB_MIX[0][x] = (t << 24) | (t >>> 8);
      SUB_MIX[1][x] = (t << 16) | (t >>> 16);
      SUB_MIX[2][x] = (t << 8) | (t >>> 24);
      SUB_MIX[3][x] = t;
      t = (x8 * 0x1010101) ^ (x4 * 0x10001) ^ (x2 * 0x101) ^ (x * 0x1010100);
      INV_SUB_MIX[0][sx] = (t << 24) | (t >>> 8);
      INV_SUB_MIX[1][sx] = (t << 16) | (t >>> 16);
      INV_SUB_MIX[2][sx] = (t << 8) | (t >>> 24);
      INV_SUB_MIX[3][sx] = t;
      if (!x) x = xi = 1;
      else {
        x = x2 ^ d[d[d[x8 ^ x2]]];
        xi ^= d[d[xi]];
      }
    }
  })();
  var RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

  var AES = (C_algo.AES = (function () {
    var BlockCipher = BufferedBlockAlgorithm.extend({
      cfg: Base.extend({ mode: null, padding: null }),
      createEncryptor: function (key, cfg) {
        return this.create(this._ENC_XFORM_MODE, key, cfg);
      },
      createDecryptor: function (key, cfg) {
        return this.create(this._DEC_XFORM_MODE, key, cfg);
      },
      init: function (xformMode, key, cfg) {
        this.cfg = this.cfg.extend(cfg);
        this._xformMode = xformMode;
        this._key = key;
        this.reset();
      },
      reset: function () {
        BufferedBlockAlgorithm.reset.call(this);
        this._doReset();
      },
      process: function (d) {
        this._append(d);
        return this._process();
      },
      finalize: function (d) {
        if (d) this._append(d);
        return this._doFinalize();
      },
      keySize: 4,
      ivSize: 4,
      _ENC_XFORM_MODE: 1,
      _DEC_XFORM_MODE: 2,
      _createHelper: function () {
        return {
          encrypt: function (m, k, cfg) {
            return selectCipher(k).encrypt(AES, m, k, cfg);
          },
          decrypt: function (m, k, cfg) {
            return selectCipher(k).decrypt(AES, m, k, cfg);
          }
        };
      }
    });
    function selectCipher(k) {
      if (typeof k === "string") return PasswordBasedCipher;
      return SerializableCipher;
    }
    var CipherParams = (C_lib.CipherParams = Base.extend({
      init: function (o) {
        this.mixIn(o);
      },
      toString: function (f) {
        return (f || this.formatter).stringify(this);
      }
    }));
    var OpenSSL = (C.format = {}).OpenSSL = {
      stringify: function (cp) {
        return cp.ciphertext.toString(Base64);
      },
      parse: function (s) {
        return CipherParams.create({ ciphertext: Base64.parse(s) });
      }
    };
    var SerializableCipher = (C_lib.SerializableCipher = Base.extend({
      cfg: Base.extend({ format: OpenSSL }),
      encrypt: function (cipher, m, k, cfg) {
        cfg = this.cfg.extend(cfg);
        var e = cipher.createEncryptor(k, cfg);
        var c = e.finalize(m);
        return CipherParams.create({
          ciphertext: c,
          key: k,
          iv: e.cfg.iv,
          algorithm: cipher,
          mode: e.cfg.mode,
          padding: e.cfg.padding,
          blockSize: cipher.blockSize,
          formatter: cfg.format
        });
      },
      decrypt: function (cipher, ct, k, cfg) {
        cfg = this.cfg.extend(cfg);
        ct = this._parse(ct, cfg.format);
        return cipher.createDecryptor(k, cfg).finalize(ct.ciphertext);
      },
      _parse: function (ct, f) {
        return typeof ct === "string" ? f.parse(ct, this) : ct;
      }
    }));
    var PasswordBasedCipher = (C_lib.PasswordBasedCipher =
      SerializableCipher.extend({
        cfg: SerializableCipher.cfg.extend({ kdf: null }),
        encrypt: function () {
          throw new Error("password not supported");
        },
        decrypt: function () {
          throw new Error("password not supported");
        }
      }));

    // CBC mode
    var CBC = (function () {
      var Mode = Base.extend({
        createEncryptor: function (c, iv) {
          return this.Encryptor.create(c, iv);
        },
        createDecryptor: function (c, iv) {
          return this.Decryptor.create(c, iv);
        },
        init: function (c, iv) {
          this._cipher = c;
          this._iv = iv;
        }
      });
      Mode.Encryptor = Mode.extend({
        processBlock: function (w, o) {
          var c = this._cipher,
            bs = c.blockSize;
          xor(w, o, this._iv || this._prevBlock, bs);
          c.encryptBlock(w, o);
          this._prevBlock = w.slice(o, o + bs);
        }
      });
      Mode.Decryptor = Mode.extend({
        processBlock: function (w, o) {
          var c = this._cipher,
            bs = c.blockSize,
            n = w.slice(o, o + bs);
          c.decryptBlock(w, o);
          xor(w, o, this._iv || this._prevBlock, bs);
          this._prevBlock = n;
        }
      });
      function xor(w, o, block, bs) {
        var b = block;
        if (this && this._iv) {
          /* first */
        }
        for (var i = 0; i < bs; i++) w[o + i] ^= b[i];
      }
      // fix xor for first block using iv
      Mode.Encryptor = Mode.extend({
        processBlock: function (words, offset) {
          var cipher = this._cipher;
          var blockSize = cipher.blockSize;
          var iv = this._iv;
          var prev = this._prevBlock;
          var block = iv ? iv : prev;
          if (iv) this._iv = undefined;
          for (var i = 0; i < blockSize; i++)
            words[offset + i] ^= block[i];
          cipher.encryptBlock(words, offset);
          this._prevBlock = words.slice(offset, offset + blockSize);
        }
      });
      Mode.Decryptor = Mode.extend({
        processBlock: function (words, offset) {
          var cipher = this._cipher;
          var blockSize = cipher.blockSize;
          var iv = this._iv;
          var thisBlock = words.slice(offset, offset + blockSize);
          cipher.decryptBlock(words, offset);
          var block = iv ? iv : this._prevBlock;
          if (iv) this._iv = undefined;
          for (var i = 0; i < blockSize; i++)
            words[offset + i] ^= block[i];
          this._prevBlock = thisBlock;
        }
      });
      return Mode;
    })();

    // PKCS7
    var PKCS7 = {
      pad: function (data, blockSize) {
        var n = blockSize * 4;
        var rem = n - (data.sigBytes % n);
        var p = (rem << 24) | (rem << 16) | (rem << 8) | rem;
        var pa = [];
        for (var i = 0; i < rem; i += 4) pa.push(p);
        data.concat(new WordArray.init(pa, rem));
      },
      unpad: function (data) {
        var n = data.words[(data.sigBytes - 1) >>> 2] & 0xff;
        data.sigBytes -= n;
      }
    };
    var NoPadding = {
      pad: function () {},
      unpad: function () {}
    };

    var AESCipher = BlockCipher.extend({
      _doReset: function () {
        var key = this._key;
        var words = key.words;
        var keySize = key.sigBytes / 4;
        var nRounds = (this._nRounds = keySize + 6);
        var ksRows = (nRounds + 1) * 4;
        var keySchedule = (this._keySchedule = []);
        for (var ksRow = 0; ksRow < ksRows; ksRow++) {
          if (ksRow < keySize) keySchedule[ksRow] = words[ksRow];
          else {
            var t = keySchedule[ksRow - 1];
            if (!(ksRow % keySize)) {
              t =
                (SBOX[(t >>> 16) & 0xff] << 24) |
                (SBOX[(t >>> 8) & 0xff] << 16) |
                (SBOX[t & 0xff] << 8) |
                SBOX[(t >>> 24) & 0xff];
              t ^= RCON[(ksRow / keySize) | 0] << 24;
            } else if (keySize > 6 && ksRow % keySize === 4) {
              t =
                (SBOX[(t >>> 24) & 0xff] << 24) |
                (SBOX[(t >>> 16) & 0xff] << 16) |
                (SBOX[(t >>> 8) & 0xff] << 8) |
                SBOX[t & 0xff];
            }
            keySchedule[ksRow] = keySchedule[ksRow - keySize] ^ t;
          }
        }
        var invKeySchedule = (this._invKeySchedule = []);
        for (var invKsRow = 0; invKsRow < ksRows; invKsRow++) {
          var ksR = ksRows - invKsRow;
          var t2 =
            invKsRow % 4
              ? keySchedule[ksR]
              : keySchedule[ksR - 4];
          if (invKsRow < 4 || ksR <= 4) invKeySchedule[invKsRow] = t2;
          else
            invKeySchedule[invKsRow] =
              INV_SUB_MIX[0][SBOX[(t2 >>> 24) & 0xff]] ^
              INV_SUB_MIX[1][SBOX[(t2 >>> 16) & 0xff]] ^
              INV_SUB_MIX[2][SBOX[(t2 >>> 8) & 0xff]] ^
              INV_SUB_MIX[3][SBOX[t2 & 0xff]];
        }
      },
      encryptBlock: function (M, offset) {
        this._doCryptBlock(
          M,
          offset,
          this._keySchedule,
          SUB_MIX,
          SBOX
        );
      },
      decryptBlock: function (M, offset) {
        var t = M[offset + 1];
        M[offset + 1] = M[offset + 3];
        M[offset + 3] = t;
        this._doCryptBlock(
          M,
          offset,
          this._invKeySchedule,
          INV_SUB_MIX,
          INV_SBOX
        );
        t = M[offset + 1];
        M[offset + 1] = M[offset + 3];
        M[offset + 3] = t;
      },
      _doCryptBlock: function (M, offset, keySchedule, SUB_MIX, SBOX) {
        var nRounds = this._nRounds;
        var s0 = M[offset] ^ keySchedule[0];
        var s1 = M[offset + 1] ^ keySchedule[1];
        var s2 = M[offset + 2] ^ keySchedule[2];
        var s3 = M[offset + 3] ^ keySchedule[3];
        var ksRow = 4;
        for (var round = 1; round < nRounds; round++) {
          var t0 =
            SUB_MIX[0][(s0 >>> 24) & 0xff] ^
            SUB_MIX[1][(s1 >>> 16) & 0xff] ^
            SUB_MIX[2][(s2 >>> 8) & 0xff] ^
            SUB_MIX[3][s3 & 0xff] ^
            keySchedule[ksRow++];
          var t1 =
            SUB_MIX[0][(s1 >>> 24) & 0xff] ^
            SUB_MIX[1][(s2 >>> 16) & 0xff] ^
            SUB_MIX[2][(s3 >>> 8) & 0xff] ^
            SUB_MIX[3][s0 & 0xff] ^
            keySchedule[ksRow++];
          var t2 =
            SUB_MIX[0][(s2 >>> 24) & 0xff] ^
            SUB_MIX[1][(s3 >>> 16) & 0xff] ^
            SUB_MIX[2][(s0 >>> 8) & 0xff] ^
            SUB_MIX[3][s1 & 0xff] ^
            keySchedule[ksRow++];
          var t3 =
            SUB_MIX[0][(s3 >>> 24) & 0xff] ^
            SUB_MIX[1][(s0 >>> 16) & 0xff] ^
            SUB_MIX[2][(s1 >>> 8) & 0xff] ^
            SUB_MIX[3][s2 & 0xff] ^
            keySchedule[ksRow++];
          s0 = t0;
          s1 = t1;
          s2 = t2;
          s3 = t3;
        }
        t0 =
          ((SBOX[(s0 >>> 24) & 0xff] << 24) |
            (SBOX[(s1 >>> 16) & 0xff] << 16) |
            (SBOX[(s2 >>> 8) & 0xff] << 8) |
            SBOX[s3 & 0xff]) ^
          keySchedule[ksRow++];
        t1 =
          ((SBOX[(s1 >>> 24) & 0xff] << 24) |
            (SBOX[(s2 >>> 16) & 0xff] << 16) |
            (SBOX[(s3 >>> 8) & 0xff] << 8) |
            SBOX[s0 & 0xff]) ^
          keySchedule[ksRow++];
        t2 =
          ((SBOX[(s2 >>> 24) & 0xff] << 24) |
            (SBOX[(s3 >>> 16) & 0xff] << 16) |
            (SBOX[(s0 >>> 8) & 0xff] << 8) |
            SBOX[s1 & 0xff]) ^
          keySchedule[ksRow++];
        t3 =
          ((SBOX[(s3 >>> 24) & 0xff] << 24) |
            (SBOX[(s0 >>> 16) & 0xff] << 16) |
            (SBOX[(s1 >>> 8) & 0xff] << 8) |
            SBOX[s2 & 0xff]) ^
          keySchedule[ksRow++];
        M[offset] = t0;
        M[offset + 1] = t1;
        M[offset + 2] = t2;
        M[offset + 3] = t3;
      },
      keySize: 8
    });

    AESCipher.mode = { CBC: CBC };
    AESCipher.pad = { Pkcs7: PKCS7, NoPadding: NoPadding };
    AESCipher.cfg = AESCipher.cfg.extend({
      mode: CBC,
      padding: PKCS7
    });

    // BlockCipher process hooks
    AESCipher._doProcessBlock = function (words, offset) {
      this._mode.processBlock(words, offset);
    };
    AESCipher._doFinalize = function () {
      var pad = this.cfg.padding;
      if (this._xformMode === this._ENC_XFORM_MODE) {
        pad.pad(this._data, this.blockSize);
        return this._process(true);
      } else {
        var final = this._process(true);
        pad.unpad(final);
        return final;
      }
    };
    AESCipher.blockSize = 4;

    // attach mode on create
    var oldInit = AESCipher.init;
    AESCipher.init = function (xformMode, key, cfg) {
      oldInit.call(this, xformMode, key, cfg);
      var modeCreator =
        this._xformMode === this._ENC_XFORM_MODE
          ? this.cfg.mode.createEncryptor
          : this.cfg.mode.createDecryptor;
      this._mode = modeCreator.call(
        this.cfg.mode,
        this,
        this.cfg.iv && this.cfg.iv.words
      );
    };

    C.AES = AESCipher._createHelper(AESCipher);
    return AESCipher;
  })());

  return C;
})();

/* ========== AES 封装（匹配哈啰：key 作 IV，解密 NoPadding 后手动去 pad） ========== */
function aesDecrypt(b64, secret) {
  var key = CryptoJS.enc.Utf8.parse(secret);
  if (key.sigBytes !== 16) throw new Error("key-len");
  var cipher = CryptoJS.enc.Base64.parse(b64);
  if (!cipher.sigBytes || cipher.sigBytes % 16 !== 0)
    throw new Error("cipher-len");
  var raw = CryptoJS.AES.decrypt({ ciphertext: cipher }, key, {
    iv: key,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.NoPadding
  });
  var len = raw.sigBytes;
  var last =
    (raw.words[(len - 1) >>> 2] >>> (24 - ((len - 1) % 4) * 8)) & 0xff;
  if (last < 1 || last > 16 || last > len) throw new Error("pad-len");
  for (var i = len - last; i < len; i++) {
    var b =
      (raw.words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
    if (b !== last) throw new Error("pad-byte");
  }
  raw.sigBytes -= last;
  raw.clamp();
  return { text: CryptoJS.enc.Utf8.stringify(raw), key: key };
}

function aesEncrypt(plain, keyWA) {
  return CryptoJS.AES.encrypt(plain, keyWA, {
    iv: keyWA,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7
  }).ciphertext.toString(CryptoJS.enc.Base64);
}

/* ========== 密钥缓存 ========== */
function loadKeys() {
  try {
    var raw = sGet(KEY_CACHE);
    if (!raw) return [];
    var arr = JSON.parse(raw);
    if (!Array.isArray(arr)) return [];
    var now = Date.now() / 1000;
    return arr.filter(function (r) {
      return r && r.s && r.v && r.f && (!r.e || r.e > now);
    }).slice(0, 3);
  } catch (e) {
    return [];
  }
}

function saveKey(secret, version, fingerprint, expires) {
  try {
    if (!secret || secret.length !== 16 || !version || !fingerprint) return;
    var list = loadKeys().filter(function (r) {
      return r.v !== version || r.f !== fingerprint;
    });
    list.unshift({
      s: secret,
      v: version,
      f: fingerprint,
      e: typeof expires === "number" ? expires : 0
    });
    sSet(KEY_CACHE, JSON.stringify(list.slice(0, 3)));
  } catch (e) {}
}

function secretsFromHeaders(headers) {
  var list = [STATIC_KEY];
  try {
    var ver = "",
      fp = "";
    if (headers) {
      for (var k in headers) {
        var lk = k.toLowerCase();
        if (lk === "key-version") ver = String(headers[k] || "");
        if (lk === "fingerprint-hash") fp = String(headers[k] || "");
      }
    }
    if (ver && fp) {
      loadKeys().forEach(function (r) {
        if (r.v === ver && r.f === fp) list.unshift(r.s);
      });
    }
  } catch (e) {}
  return list;
}

/* ========== 打开 body ========== */
function openBody(body, secrets) {
  var text = (body || "").trim();
  var quoted = false;
  if (text.charAt(0) === "{" || text.charAt(0) === "[")
    return { text: text, mode: "plain", key: null, quoted: false };
  if (text.charAt(0) === '"') {
    text = JSON.parse(text);
    quoted = true;
  }
  if (typeof text !== "string" || text.length % 4 !== 0)
    throw new Error("format");
  for (var i = 0; i < secrets.length; i++) {
    try {
      var dec = aesDecrypt(text, secrets[i]);
      var obj = JSON.parse(dec.text);
      if (obj && typeof obj === "object")
        return { text: dec.text, mode: "aes", key: dec.key, quoted: quoted };
    } catch (e) {}
  }
  throw new Error("decrypt");
}

/* ========== 只清弹窗 + 信息流 ========== */
function isObj(v) {
  return v && typeof v === "object" && !Array.isArray(v);
}

function clean(obj) {
  if (!isObj(obj) || !("data" in obj)) return false;
  var changed = false;
  var data = obj.data;

  // 弹窗
  if (Array.isArray(data)) {
    var bad = {
      marketAd: 1,
      financeRecommendPopup: 1,
      activityAppUsageScene: 1,
      newAttributionPopup: 1,
      attributionPopup: 1,
      newChannelAttrPopup: 1
    };
    var kept = data.filter(function (item) {
      if (!isObj(item)) return true;
      var t = item.popupWindowType;
      return !t || !bad[t];
    });
    if (kept.length !== data.length) {
      obj.data = kept;
      changed = true;
    }
  }

  // 信息流 / 瀑布流
  if (isObj(data)) {
    if (Array.isArray(data.list) && data.list.length) {
      data.list = [];
      if ("hasMore" in data) data.hasMore = false;
      changed = true;
    }
    if (Array.isArray(data.materialList) && data.materialList.length) {
      data.materialList = [];
      if ("needRequest" in data) data.needRequest = false;
      changed = true;
    }
    if (Array.isArray(data.moduleList)) {
      var before = data.moduleList.length;
      data.moduleList = data.moduleList.filter(function (m) {
        if (!isObj(m) || typeof m.moduleKey !== "string") return true;
        return (
          m.moduleKey !== "homepage_feeds_module" &&
          m.moduleKey !== "homepage_waterfall_module"
        );
      });
      if (data.moduleList.length !== before) changed = true;
    }
  }

  // 广告 creative
  if (isObj(data) && Array.isArray(data.adm)) {
    for (var i = 0; i < data.adm.length; i++) {
      var ad = data.adm[i];
      if (!isObj(ad)) continue;
      if (Array.isArray(ad.creative) && ad.creative.length) {
        ad.creative = [];
        changed = true;
      }
      if (Array.isArray(ad.backupCreative) && ad.backupCreative.length) {
        ad.backupCreative = [];
        changed = true;
      }
    }
  }

  return changed;
}

/* ========== 主流程 ========== */
(function () {
  var req = typeof $request === "object" && $request ? $request : {};
  var res = typeof $response === "object" && $response ? $response : null;
  var url = String(req.url || "");

  // 捕获密钥
  if (/\/secretkey(?:\?|$)/i.test(url) && res && typeof res.body === "string") {
    try {
      var opened = openBody(res.body, [STATIC_KEY]);
      var o = JSON.parse(opened.text);
      if (
        o &&
        (o.code === 0 || o.code === "0") &&
        isObj(o.data) &&
        o.data.key
      ) {
        var d = o.data;
        var exp =
          typeof d.expired === "number"
            ? d.expired
            : typeof d.expired === "string"
            ? Number(d.expired)
            : 0;
        saveKey(
          d.key,
          d["key-version"],
          d["fingerprint-hash"],
          exp
        );
      }
    } catch (e) {}
    $done({});
    return;
  }

  if (!res || typeof res.body !== "string" || !res.body) {
    $done({});
    return;
  }
  if (res.body.length > MAX_SIZE) {
    $done({});
    return;
  }
  if (Number(res.statusCode || 200) !== 200) {
    $done({});
    return;
  }
  if (!/hellobike\.com\/api/i.test(url)) {
    $done({});
    return;
  }

  try {
    var secrets = secretsFromHeaders(req.headers);
    var opened = openBody(res.body, secrets);
    var obj = JSON.parse(opened.text);
    if (!isObj(obj)) {
      $done({});
      return;
    }
    if (!clean(obj)) {
      $done({});
      return;
    }
    var out = JSON.stringify(obj);
    if (opened.mode === "aes" && opened.key) {
      out = aesEncrypt(out, opened.key);
      if (opened.quoted) out = JSON.stringify(out);
    }
    $done({ body: out });
  } catch (e) {
    $done({});
  }
})();
