/**
 * 诀别 - 卡密验证系统 v3.0
 * 纯前端 AES-128 加密验证，无需后端服务器
 */
(function() {
  'use strict';

  // ============================================================
  //  1. 配置 - 卡密种子密钥（16字节用于AES-128）
  // ============================================================
  const SECRET_KEY = new Uint8Array([
    0x4A, 0x75, 0x65, 0x42, 0x69, 0x65, 0x32, 0x30,
    0x32, 0x36, 0x53, 0x65, 0x63, 0x72, 0x65, 0x74
  ]);

  const IV = new Uint8Array([
    0x58, 0x44, 0x4B, 0x65, 0x79, 0x33, 0x30, 0x30,
    0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  ]);

  // 卡密格式校验正则：XXXX-XXXX-XXXX-XXXX
  const CARD_REGEX = /^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/;

  // 存储键名
  const STORAGE_KEY = '_juebie_license';
  const STORAGE_SALT = '_juebie_salt';

  // ============================================================
  //  2. AES-128-CBC 实现（纯 JS，无外部依赖）
  // ============================================================

  // S-Box
  const SBOX = new Uint8Array([
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
  ]);

  const INV_SBOX = new Uint8Array([
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
  ]);

  const RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

  // GF(2^8) 乘法
  function gmul(a, b) {
    let p = 0;
    for (let i = 0; i < 8; i++) {
      if (b & 1) p ^= a;
      let hi = a & 0x80;
      a = (a << 1) & 0xff;
      if (hi) a ^= 0x1b;
      b >>= 1;
    }
    return p;
  }

  function subBytes(state) {
    for (let i = 0; i < 16; i++) state[i] = SBOX[state[i]];
  }

  function invSubBytes(state) {
    for (let i = 0; i < 16; i++) state[i] = INV_SBOX[state[i]];
  }

  function shiftRows(state) {
    let t = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = t;
    t = state[2]; state[2] = state[10]; state[10] = t; t = state[6]; state[6] = state[14]; state[14] = t;
    t = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = t;
  }

  function invShiftRows(state) {
    let t = state[13]; state[13] = state[9]; state[9] = state[5]; state[5] = state[1]; state[1] = t;
    t = state[2]; state[2] = state[10]; state[10] = t; t = state[6]; state[6] = state[14]; state[14] = t;
    t = state[3]; state[3] = state[7]; state[7] = state[11]; state[11] = state[15]; state[15] = t;
  }

  function mixColumns(state) {
    for (let i = 0; i < 16; i += 4) {
      let a0 = state[i], a1 = state[i+1], a2 = state[i+2], a3 = state[i+3];
      state[i]   = gmul(2, a0) ^ gmul(3, a1) ^ a2 ^ a3;
      state[i+1] = a0 ^ gmul(2, a1) ^ gmul(3, a2) ^ a3;
      state[i+2] = a0 ^ a1 ^ gmul(2, a2) ^ gmul(3, a3);
      state[i+3] = gmul(3, a0) ^ a1 ^ a2 ^ gmul(2, a3);
    }
  }

  function invMixColumns(state) {
    for (let i = 0; i < 16; i += 4) {
      let a0 = state[i], a1 = state[i+1], a2 = state[i+2], a3 = state[i+3];
      state[i]   = gmul(14,a0) ^ gmul(11,a1) ^ gmul(13,a2) ^ gmul(9,a3);
      state[i+1] = gmul(9,a0)  ^ gmul(14,a1) ^ gmul(11,a2) ^ gmul(13,a3);
      state[i+2] = gmul(13,a0) ^ gmul(9,a1)  ^ gmul(14,a2) ^ gmul(11,a3);
      state[i+3] = gmul(11,a0) ^ gmul(13,a1) ^ gmul(9,a2)  ^ gmul(14,a3);
    }
  }

  function addRoundKey(state, roundKey) {
    for (let i = 0; i < 16; i++) state[i] ^= roundKey[i];
  }

  function keyExpansion(key) {
    let w = new Uint8Array(176);
    for (let i = 0; i < 16; i++) w[i] = key[i];
    for (let i = 16; i < 176; i += 4) {
      let temp = [w[i-4], w[i-3], w[i-2], w[i-1]];
      if (i % 16 === 0) {
        temp = [SBOX[temp[1]] ^ RCON[(i/16)-1], SBOX[temp[2]], SBOX[temp[3]], SBOX[temp[0]]];
      }
      w[i]   = w[i-16] ^ temp[0];
      w[i+1] = w[i-15] ^ temp[1];
      w[i+2] = w[i-14] ^ temp[2];
      w[i+3] = w[i-13] ^ temp[3];
    }
    return w;
  }

  function aesEncryptBlock(plaintext, key) {
    let state = new Uint8Array(plaintext);
    let w = keyExpansion(key);
    addRoundKey(state, w.slice(0, 16));
    for (let r = 1; r < 10; r++) {
      subBytes(state);
      shiftRows(state);
      mixColumns(state);
      addRoundKey(state, w.slice(r*16, r*16+16));
    }
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, w.slice(160, 176));
    return state;
  }

  function aesDecryptBlock(ciphertext, key) {
    let state = new Uint8Array(ciphertext);
    let w = keyExpansion(key);
    addRoundKey(state, w.slice(160, 176));
    for (let r = 9; r >= 1; r--) {
      invShiftRows(state);
      invSubBytes(state);
      addRoundKey(state, w.slice(r*16, r*16+16));
      invMixColumns(state);
    }
    invShiftRows(state);
    invSubBytes(state);
    addRoundKey(state, w.slice(0, 16));
    return state;
  }

  // PKCS7 padding
  function pkcs7Pad(data, blockSize) {
    let padLen = blockSize - (data.length % blockSize);
    let result = new Uint8Array(data.length + padLen);
    result.set(data);
    result.fill(padLen, data.length);
    return result;
  }

  function pkcs7Unpad(data) {
    let padLen = data[data.length - 1];
    if (padLen < 1 || padLen > 16) return null;
    return data.slice(0, data.length - padLen);
  }

  function aesCbcEncrypt(plaintext, key, iv) {
    let padded = pkcs7Pad(plaintext, 16);
    let result = new Uint8Array(padded.length);
    let prevBlock = new Uint8Array(iv);
    for (let i = 0; i < padded.length; i += 16) {
      let block = padded.slice(i, i + 16);
      for (let j = 0; j < 16; j++) block[j] ^= prevBlock[j];
      prevBlock = aesEncryptBlock(block, key);
      result.set(prevBlock, i);
    }
    return result;
  }

  function aesCbcDecrypt(ciphertext, key, iv) {
    let result = new Uint8Array(ciphertext.length);
    let prevBlock = new Uint8Array(iv);
    for (let i = 0; i < ciphertext.length; i += 16) {
      let decrypted = aesDecryptBlock(ciphertext.slice(i, i + 16), key);
      for (let j = 0; j < 16; j++) decrypted[j] ^= prevBlock[j];
      prevBlock = ciphertext.slice(i, i + 16);
      result.set(decrypted, i);
    }
    return pkcs7Unpad(result);
  }

  // ============================================================
  //  3. 数据编解码工具
  // ============================================================
  function strToBytes(str) {
    let bytes = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i);
    return bytes;
  }

  function bytesToStr(bytes) {
    return String.fromCharCode.apply(null, bytes);
  }

  function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function hexToBytes(hex) {
    let bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) bytes[i/2] = parseInt(hex.substr(i, 2), 16);
    return bytes;
  }

  // Base64 编解码
  function base64Encode(bytes) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    let result = '';
    for (let i = 0; i < bytes.length; i += 3) {
      let b = (bytes[i] << 16) | (bytes[i+1] << 8) | (bytes[i+2] || 0);
      result += chars[(b >> 18) & 63] + chars[(b >> 12) & 63];
      result += i + 1 < bytes.length ? chars[(b >> 6) & 63] : '=';
      result += i + 2 < bytes.length ? chars[b & 63] : '=';
    }
    return result;
  }

  function base64Decode(str) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    str = str.replace(/=+$/, '');
    let bytes = [];
    for (let i = 0; i < str.length; i += 4) {
      let b0 = chars.indexOf(str[i]), b1 = chars.indexOf(str[i+1]);
      let b2 = str[i+2] ? chars.indexOf(str[i+2]) : 0;
      let b3 = str[i+3] ? chars.indexOf(str[i+3]) : 0;
      let val = (b0 << 18) | (b1 << 12) | (b2 << 6) | b3;
      bytes.push((val >> 16) & 255);
      if (str[i+2] && str[i+2] !== '=') bytes.push((val >> 8) & 255);
      if (str[i+3] && str[i+3] !== '=') bytes.push(val & 255);
    }
    return new Uint8Array(bytes);
  }

  // 设备指纹（简易）
  function getDeviceFingerprint() {
    let fp = '';
    fp += navigator.hardwareConcurrency || '';
    fp += navigator.maxTouchPoints || '';
    fp += screen.width + 'x' + screen.height;
    fp += navigator.language || '';
    fp += (navigator.platform || '') + '|';
    // 取指纹的前32字符作为标识
    let hash = 0;
    for (let i = 0; i < fp.length; i++) {
      hash = ((hash << 5) - hash) + fp.charCodeAt(i);
      hash |= 0;
    }
    return 'FP' + Math.abs(hash).toString(16).toUpperCase().padStart(8, '0').slice(0, 8);
  }

  // ============================================================
  //  4. 加密存储
  // ============================================================
  function encryptData(plainData) {
    let json = JSON.stringify(plainData);
    let plainBytes = strToBytes(json);
    let encrypted = aesCbcEncrypt(plainBytes, SECRET_KEY, IV);
    return base64Encode(encrypted);
  }

  function decryptData(encryptedB64) {
    try {
      let encrypted = base64Decode(encryptedB64);
      let decrypted = aesCbcDecrypt(encrypted, SECRET_KEY, IV);
      if (!decrypted) return null;
      return JSON.parse(bytesToStr(decrypted));
    } catch (e) {
      return null;
    }
  }

  // ============================================================
  //  5. 卡密验证核心
  // ============================================================
  function parseCardKey(cardKey) {
    // 卡密格式: XXXX-XXXX-XXXX-XXXX
    // 前16位是有效载荷，包含: 版本(2) + 时长(2) + 序号(4) + 随机(4) + 校验(4)
    let clean = cardKey.replace(/-/g, '');
    if (clean.length !== 16) return null;

    let version = clean.substring(0, 2);
    let daysHex = clean.substring(2, 4);
    let serialHex = clean.substring(4, 8);
    let randHex = clean.substring(8, 12);
    let checksum = clean.substring(12, 16);

    let days = parseInt(daysHex, 16);
    let serial = parseInt(serialHex, 16);

    // 验证校验和
    let payload = clean.substring(0, 12);
    let expectedChecksum = simpleChecksum(payload);
    if (checksum.toUpperCase() !== expectedChecksum.toUpperCase()) return null;

    // 版本检查（必须是 V1 即 "01"）
    if (version !== '01') return null;

    // 天数范围检查（1-365天）
    if (days < 1 || days > 365) return null;

    return { version, days, serial, raw: cardKey };
  }

  function simpleChecksum(data) {
    // 简单但有效的校验算法
    let hash = 0xABCD;
    for (let i = 0; i < data.length; i++) {
      let c = data.charCodeAt(i);
      hash = ((hash << 5) - hash + c * (i + 1) * 7) & 0xFFFF;
      hash ^= (hash >> 8);
    }
    return hash.toString(16).toUpperCase().padStart(4, '0');
  }

  /**
   * 验证卡密是否有效
   * @param {string} cardKey - 卡密字符串
   * @param {string} checkCode - 校验码（可选）
   * @returns {object|null} 验证结果或null
   */
  function validateCardKey(cardKey, checkCode) {
    // 1. 格式校验
    if (!CARD_REGEX.test(cardKey)) {
      return { valid: false, error: '卡密格式不正确，请使用 XXXX-XXXX-XXXX-XXXX 格式' };
    }

    // 2. 解析并验证卡密
    let parsed = parseCardKey(cardKey);
    if (!parsed) {
      return { valid: false, error: '卡密校验失败，请检查是否输入正确' };
    }

    // 3. 检查是否已被使用（本地存储中查重）
    let existing = getStoredLicense();
    if (existing && existing.cards) {
      for (let c of existing.cards) {
        if (c.raw === cardKey) {
          return { valid: false, error: '此卡密已被使用过' };
        }
      }
    }

    // 4. 检查校验码（如果提供）
    if (checkCode) {
      let expectedCheckCode = generateCheckCode(cardKey);
      if (checkCode.toUpperCase() !== expectedCheckCode.toUpperCase()) {
        return { valid: false, error: '校验码不匹配' };
      }
    }

    // 5. 验证通过
    return {
      valid: true,
      days: parsed.days,
      serial: parsed.serial,
      cardKey: cardKey
    };
  }

  /**
   * 根据卡密生成校验码
   */
  function generateCheckCode(cardKey) {
    let clean = cardKey.replace(/-/g, '');
    // 使用不同的哈希算法生成6位校验码
    let hash = 0x3F8A9C;
    for (let i = 0; i < clean.length; i++) {
      let c = clean.charCodeAt(i);
      hash = ((hash * 31 + c * (i + 3) * 13) & 0xFFFFFF) ^ (hash >> 12);
    }
    return hash.toString(16).toUpperCase().padStart(6, '0').slice(0, 6);
  }

  /**
   * 激活卡密
   */
  function activateCard(cardKey) {
    let result = validateCardKey(cardKey);
    if (!result.valid) return result;

    let now = new Date();
    let expireDate = new Date(now.getTime() + result.days * 24 * 60 * 60 * 1000);

    let license = getStoredLicense() || { cards: [], deviceFingerprint: getDeviceFingerprint() };

    // 添加新卡密
    license.cards.push({
      raw: cardKey,
      days: result.days,
      activatedAt: now.toISOString(),
      expiresAt: expireDate.toISOString(),
      serial: result.serial
    });

    // 重新计算总到期时间（取最晚的）
    let maxExpire = new Date(0);
    for (let c of license.cards) {
      let exp = new Date(c.expiresAt);
      if (exp > maxExpire) maxExpire = exp;
    }
    license.expiresAt = maxExpire.toISOString();
    license.lastCheck = now.toISOString();
    license.activated = true;

    // 加密存储
    saveStoredLicense(license);

    return {
      valid: true,
      days: result.days,
      expiresAt: maxExpire,
      message: '激活成功！有效期至 ' + formatDate(maxExpire)
    };
  }

  /**
   * 检查当前授权状态
   */
  function checkLicense() {
    let license = getStoredLicense();
    if (!license || !license.activated || !license.cards || license.cards.length === 0) {
      return { activated: false, reason: '未激活' };
    }

    // 检查设备指纹
    let currentFp = getDeviceFingerprint();
    if (license.deviceFingerprint && license.deviceFingerprint !== currentFp) {
      return { activated: false, reason: '设备不匹配' };
    }

    // 检查是否过期
    let now = new Date();
    let expiresAt = new Date(license.expiresAt);

    if (now > expiresAt) {
      return { activated: false, reason: '已过期', expiresAt: expiresAt };
    }

    // 计算剩余天数
    let remainingMs = expiresAt.getTime() - now.getTime();
    let remainingDays = Math.ceil(remainingMs / (24 * 60 * 60 * 1000));
    let remainingHours = Math.ceil(remainingMs / (60 * 60 * 1000));

    // 更新最后检查时间
    license.lastCheck = now.toISOString();
    saveStoredLicense(license);

    return {
      activated: true,
      expiresAt: expiresAt,
      remainingDays: remainingDays,
      remainingHours: remainingHours,
      totalCards: license.cards.length,
      isExpiringSoon: remainingDays <= 3
    };
  }

  /**
   * 获取存储的授权信息
   */
  function getStoredLicense() {
    try {
      let raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return null;
      return decryptData(raw);
    } catch (e) {
      return null;
    }
  }

  /**
   * 保存授权信息
   */
  function saveStoredLicense(license) {
    try {
      let encrypted = encryptData(license);
      localStorage.setItem(STORAGE_KEY, encrypted);
      // 同时存一个防篡改盐值
      let salt = simpleChecksum(encrypted);
      localStorage.setItem(STORAGE_SALT, salt);
    } catch (e) {
      console.error('[诀别] 保存授权失败:', e);
    }
  }

  /**
   * 验证存储完整性
   */
  function verifyStorageIntegrity() {
    try {
      let raw = localStorage.getItem(STORAGE_KEY);
      let salt = localStorage.getItem(STORAGE_SALT);
      if (!raw) return true; // 没有存储也算合法
      if (!salt) return false;
      return simpleChecksum(raw) === salt;
    } catch (e) {
      return false;
    }
  }

  /**
   * 重置授权（清除所有卡密）
   */
  function resetLicense() {
    localStorage.removeItem(STORAGE_KEY);
    localStorage.removeItem(STORAGE_SALT);
    return { success: true, message: '授权已重置' };
  }

  function formatDate(date) {
    let y = date.getFullYear();
    let m = String(date.getMonth() + 1).padStart(2, '0');
    let d = String(date.getDate()).padStart(2, '0');
    let h = String(date.getHours()).padStart(2, '0');
    let min = String(date.getMinutes()).padStart(2, '0');
    return `${y}-${m}-${d} ${h}:${min}`;
  }

  // ============================================================
  //  6. 卡密生成器（仅用于生成新卡密）
  // ============================================================
  function generateCardKey(serial, days) {
    let version = '01'; // 版本号
    let daysHex = days.toString(16).toUpperCase().padStart(2, '0');
    let serialHex = serial.toString(16).toUpperCase().padStart(4, '0');

    // 生成4位随机数
    let rand = Math.floor(Math.random() * 0xFFFF);
    let randHex = rand.toString(16).toUpperCase().padStart(4, '0');

    let payload = version + daysHex + serialHex + randHex;
    let checksum = simpleChecksum(payload);
    let fullKey = payload + checksum;

    // 格式化为 XXXX-XXXX-XXXX-XXXX
    return [
      fullKey.substring(0, 4),
      fullKey.substring(4, 8),
      fullKey.substring(8, 12),
      fullKey.substring(12, 16)
    ].join('-');
  }

  // ============================================================
  //  7. 暴露 API
  // ============================================================
  window.JueBieLicense = {
    validate: validateCardKey,
    activate: activateCard,
    check: checkLicense,
    reset: resetLicense,
    generateCheckCode: generateCheckCode,
    generateCard: generateCardKey,
    getStored: getStoredLicense,
    verifyIntegrity: verifyStorageIntegrity,
    getDeviceFingerprint: getDeviceFingerprint
  };

  console.log('[诀别] 卡密验证系统 v3.0 已加载');

})();
