import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';

function cleanEnvValue(value) {
  if (value === undefined || value === null) return '';
  let v = String(value).trim();
  if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
    v = v.slice(1, -1).trim();
  }
  return v;
}

function requireEnv(env, name) {
  const value = cleanEnvValue(env[name]);
  if (!value) throw new Error(`Missing environment variable: ${name}`);
  return value;
}

function getConfig(env) {
  const token = requireEnv(env, 'WECHAT_TOKEN');
  let encodingAesKey = requireEnv(env, 'WECHAT_ENCODING_AES_KEY');
  const corpId = requireEnv(env, 'WECHAT_CORP_ID');

  // 企业微信 EncodingAESKey 标准长度是 43 位，不需要带末尾的 =
  encodingAesKey = encodingAesKey.replace(/=+$/g, '').trim();

  if (encodingAesKey.length !== 43) {
    throw new Error(`WECHAT_ENCODING_AES_KEY length invalid: expected 43, got ${encodingAesKey.length}`);
  }

  const aesKey = Buffer.from(`${encodingAesKey}=`, 'base64');
  if (aesKey.length !== 32) {
    throw new Error(`WECHAT_ENCODING_AES_KEY decode invalid: expected 32 bytes, got ${aesKey.length}`);
  }

  return { token, encodingAesKey, corpId, aesKey };
}

function sha1(text) {
  return createHash('sha1').update(text, 'utf8').digest('hex');
}

function calcSignature(token, timestamp, nonce, encrypt) {
  return sha1([token, timestamp, nonce, encrypt].sort().join(''));
}

function checkSignature(token, signature, timestamp, nonce, encrypt) {
  if (!signature || !timestamp || !nonce || !encrypt) return false;
  return calcSignature(token, timestamp, nonce, encrypt) === signature;
}

function pkcs7Pad(buffer, blockSize = 32) {
  const padLen = blockSize - (buffer.length % blockSize);
  return Buffer.concat([buffer, Buffer.alloc(padLen, padLen)]);
}

function pkcs7Unpad(buffer) {
  if (!buffer.length) throw new Error('Invalid PKCS7 padding: empty buffer');
  const pad = buffer[buffer.length - 1];
  if (pad < 1 || pad > 32) throw new Error(`Invalid PKCS7 padding: ${pad}`);
  return buffer.subarray(0, buffer.length - pad);
}

function decryptMsg(encryptText, config) {
  const decipher = createDecipheriv('aes-256-cbc', config.aesKey, config.aesKey.subarray(0, 16));
  decipher.setAutoPadding(false);

  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(encryptText, 'base64')),
    decipher.final(),
  ]);

  const unpadded = pkcs7Unpad(decrypted);
  if (unpadded.length < 20) throw new Error('Decrypted payload too short');

  const content = unpadded.subarray(16);
  const xmlLen = content.readUInt32BE(0);
  const xmlContent = content.subarray(4, 4 + xmlLen).toString('utf8');
  const receiveId = content.subarray(4 + xmlLen).toString('utf8');

  if (receiveId !== config.corpId) {
    throw new Error(`ReceiveId mismatch: expected ${config.corpId}, got ${receiveId}`);
  }

  return xmlContent;
}

function encryptMsg(replyXml, nonce, timestamp, config) {
  const randomStr = randomBytes(16);
  const xmlBytes = Buffer.from(replyXml, 'utf8');
  const msgLen = Buffer.alloc(4);
  msgLen.writeUInt32BE(xmlBytes.length, 0);
  const corpIdBytes = Buffer.from(config.corpId, 'utf8');

  const rawMsg = Buffer.concat([randomStr, msgLen, xmlBytes, corpIdBytes]);
  const paddedMsg = pkcs7Pad(rawMsg, 32);

  const cipher = createCipheriv('aes-256-cbc', config.aesKey, config.aesKey.subarray(0, 16));
  cipher.setAutoPadding(false);
  const encrypted = Buffer.concat([cipher.update(paddedMsg), cipher.final()]).toString('base64');

  const msgSignature = calcSignature(config.token, timestamp, nonce, encrypted);

  return `<xml>
  <Encrypt><![CDATA[${encrypted}]]></Encrypt>
  <MsgSignature><![CDATA[${msgSignature}]]></MsgSignature>
  <TimeStamp>${timestamp}</TimeStamp>
  <Nonce><![CDATA[${nonce}]]></Nonce>
</xml>`;
}

function extractXmlTag(xml, tag) {
  const re = new RegExp(`<${tag}>([\\s\\S]*?)<\\/${tag}>`, 'i');
  const match = xml.match(re);
  if (!match) return '';
  return match[1].replace(/^<!\[CDATA\[/, '').replace(/\]\]>$/, '');
}

function cdata(value) {
  return String(value ?? '').replace(/\]\]>/g, ']]]]><![CDATA[>');
}

function nowTimestamp() {
  // Unix 时间戳不分时区，不能手动 +8 小时
  return String(Math.floor(Date.now() / 1000));
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  });
}

async function handleCallback(request, env) {
  const config = getConfig(env);
  const url = new URL(request.url);
  const signature = url.searchParams.get('msg_signature');
  const timestamp = url.searchParams.get('timestamp');
  const nonce = url.searchParams.get('nonce');

  console.log('callback request', {
    method: request.method,
    path: url.pathname,
    has_signature: Boolean(signature),
    has_timestamp: Boolean(timestamp),
    has_nonce: Boolean(nonce),
    colo: request.cf?.colo,
  });

  if (request.method === 'GET') {
    const echostr = url.searchParams.get('echostr');

    if (!signature || !timestamp || !nonce || !echostr) {
      return new Response('Missing required query parameters', { status: 400 });
    }

    const computed = calcSignature(config.token, timestamp, nonce, echostr);
    console.log('GET signature check', {
      matched: computed === signature,
      received_prefix: signature.slice(0, 8),
      computed_prefix: computed.slice(0, 8),
      echostr_len: echostr.length,
    });

    if (computed !== signature) {
      return new Response('signature error', { status: 403 });
    }

    try {
      const plainText = decryptMsg(echostr, config);
      console.log('GET decrypt ok', { plaintext_len: plainText.length });
      return new Response(plainText, {
        headers: { 'content-type': 'text/plain; charset=utf-8' },
      });
    } catch (err) {
      console.error('GET decrypt error', err.message);
      return new Response(`decrypt error: ${err.message}`, { status: 500 });
    }
  }

  if (request.method === 'POST') {
    const xmlData = await request.text();
    const encrypt = extractXmlTag(xmlData, 'Encrypt');

    if (!signature || !timestamp || !nonce || !encrypt) {
      return new Response('Missing required POST parameters', { status: 400 });
    }

    const computed = calcSignature(config.token, timestamp, nonce, encrypt);
    console.log('POST signature check', {
      matched: computed === signature,
      received_prefix: signature.slice(0, 8),
      computed_prefix: computed.slice(0, 8),
      encrypt_len: encrypt.length,
    });

    if (computed !== signature) {
      return new Response('signature error', { status: 403 });
    }

    try {
      const decryptedXml = decryptMsg(encrypt, config);
      const msgType = extractXmlTag(decryptedXml, 'MsgType');
      const fromUserName = extractXmlTag(decryptedXml, 'FromUserName');
      const toUserName = extractXmlTag(decryptedXml, 'ToUserName');
      const content = msgType === 'text' ? extractXmlTag(decryptedXml, 'Content') : '非文本消息';

      console.log('POST decrypt ok', { msgType, content_len: content.length });

      const replyXml = `<xml>
  <ToUserName><![CDATA[${cdata(fromUserName)}]]></ToUserName>
  <FromUserName><![CDATA[${cdata(toUserName)}]]></FromUserName>
  <CreateTime>${nowTimestamp()}</CreateTime>
  <MsgType><![CDATA[text]]></MsgType>
  <Content><![CDATA[收到你的消息: ${cdata(content)}]]></Content>
</xml>`;

      return new Response(encryptMsg(replyXml, nonce, timestamp, config), {
        headers: { 'content-type': 'application/xml; charset=utf-8' },
      });
    } catch (err) {
      console.error('POST decrypt/process error', err.message);
      return new Response(`decrypt error: ${err.message}`, { status: 500 });
    }
  }

  return new Response('Method Not Allowed', { status: 405 });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    try {
      if (url.pathname === '/' || url.pathname === '/health') {
        return new Response('wechat-callback worker ok', {
          headers: { 'content-type': 'text/plain; charset=utf-8' },
        });
      }

      if (url.pathname === '/debug-env') {
        let configOk = false;
        let error = '';
        let info = {};
        try {
          const token = cleanEnvValue(env.WECHAT_TOKEN);
          const encodingAesKeyRaw = cleanEnvValue(env.WECHAT_ENCODING_AES_KEY);
          const encodingAesKey = encodingAesKeyRaw.replace(/=+$/g, '').trim();
          const corpId = cleanEnvValue(env.WECHAT_CORP_ID);
          const aesKey = encodingAesKey ? Buffer.from(`${encodingAesKey}=`, 'base64') : Buffer.alloc(0);
          getConfig(env);
          configOk = true;
          info = {
            token_set: Boolean(token),
            token_len: token.length,
            encoding_aes_key_set: Boolean(encodingAesKeyRaw),
            encoding_aes_key_len_after_trim: encodingAesKey.length,
            aes_key_decoded_bytes: aesKey.length,
            corp_id_set: Boolean(corpId),
            corp_id_len: corpId.length,
          };
        } catch (e) {
          error = e.message;
        }
        return jsonResponse({ ok: configOk, error, ...info });
      }

      if (url.pathname === '/time-check') {
        return jsonResponse({
          unix_timestamp: nowTimestamp(),
          iso_utc: new Date().toISOString(),
          note: 'Unix timestamp is timezone-independent. Do not add 8 hours.',
          colo: request.cf?.colo || null,
        });
      }

      if (url.pathname === '/callback') {
        return handleCallback(request, env);
      }

      return new Response('Not Found', { status: 404 });
    } catch (err) {
      console.error('global error', err.message);
      return new Response(`Server error: ${err.message}`, { status: 500 });
    }
  },
};
