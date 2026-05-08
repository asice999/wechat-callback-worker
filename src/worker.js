import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';

function requireEnv(env, name) {
  const value = env[name];
  if (!value) throw new Error(`Missing environment variable: ${name}`);
  return value;
}

function getConfig(env) {
  const token = requireEnv(env, 'WECHAT_TOKEN');
  const encodingAesKey = requireEnv(env, 'WECHAT_ENCODING_AES_KEY');
  const corpId = requireEnv(env, 'WECHAT_CORP_ID');

  const aesKey = Buffer.from(`${encodingAesKey}=`, 'base64');
  if (aesKey.length !== 32) {
    throw new Error('WECHAT_ENCODING_AES_KEY is invalid: decoded key must be 32 bytes');
  }

  return { token, encodingAesKey, corpId, aesKey };
}

function sha1(text) {
  return createHash('sha1').update(text, 'utf8').digest('hex');
}

function checkSignature(token, signature, timestamp, nonce, encrypt) {
  if (!signature || !timestamp || !nonce || !encrypt) return false;
  const raw = [token, timestamp, nonce, encrypt].sort().join('');
  return sha1(raw) === signature;
}

function pkcs7Pad(buffer, blockSize = 32) {
  const padLen = blockSize - (buffer.length % blockSize);
  return Buffer.concat([buffer, Buffer.alloc(padLen, padLen)]);
}

function pkcs7Unpad(buffer) {
  if (!buffer.length) throw new Error('Invalid PKCS7 padding: empty buffer');
  const pad = buffer[buffer.length - 1];
  if (pad < 1 || pad > 32) throw new Error('Invalid PKCS7 padding');
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
  const content = unpadded.subarray(16);
  const xmlLen = content.readUInt32BE(0);
  const xmlContent = content.subarray(4, 4 + xmlLen).toString('utf8');
  const corpId = content.subarray(4 + xmlLen).toString('utf8');

  if (corpId !== config.corpId) {
    throw new Error('CorpID mismatch');
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

  const signature = sha1([config.token, timestamp, nonce, encrypted].sort().join(''));

  return `<xml>
  <Encrypt><![CDATA[${encrypted}]]></Encrypt>
  <MsgSignature><![CDATA[${signature}]]></MsgSignature>
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

async function handleCallback(request, env) {
  const config = getConfig(env);
  const url = new URL(request.url);
  const signature = url.searchParams.get('msg_signature');
  const timestamp = url.searchParams.get('timestamp') || String(Math.floor(Date.now() / 1000));
  const nonce = url.searchParams.get('nonce') || randomBytes(8).toString('hex');

  if (request.method === 'GET') {
    const echostr = url.searchParams.get('echostr');
    if (!signature || !timestamp || !nonce || !echostr) {
      return new Response('Missing required query parameters', { status: 400 });
    }
    if (!checkSignature(config.token, signature, timestamp, nonce, echostr)) {
      return new Response('signature error', { status: 403 });
    }

    try {
      return new Response(decryptMsg(echostr, config), {
        headers: { 'content-type': 'text/plain; charset=utf-8' },
      });
    } catch (err) {
      return new Response(`decrypt error: ${err.message}`, { status: 500 });
    }
  }

  if (request.method === 'POST') {
    const xmlData = await request.text();
    const encrypt = extractXmlTag(xmlData, 'Encrypt');

    if (!signature || !timestamp || !nonce || !encrypt) {
      return new Response('Missing required POST parameters', { status: 400 });
    }
    if (!checkSignature(config.token, signature, timestamp, nonce, encrypt)) {
      return new Response('signature error', { status: 403 });
    }

    try {
      const decryptedXml = decryptMsg(encrypt, config);
      const msgType = extractXmlTag(decryptedXml, 'MsgType');
      const fromUserName = extractXmlTag(decryptedXml, 'FromUserName');
      const toUserName = extractXmlTag(decryptedXml, 'ToUserName');
      const content = msgType === 'text' ? extractXmlTag(decryptedXml, 'Content') : '非文本消息';

      console.log(`解密后消息类型: ${msgType}, 内容: ${content}`);

      const replyXml = `<xml>
  <ToUserName><![CDATA[${cdata(fromUserName)}]]></ToUserName>
  <FromUserName><![CDATA[${cdata(toUserName)}]]></FromUserName>
  <CreateTime>${Math.floor(Date.now() / 1000)}</CreateTime>
  <MsgType><![CDATA[text]]></MsgType>
  <Content><![CDATA[收到你的消息: ${cdata(content)}]]></Content>
</xml>`;

      return new Response(encryptMsg(replyXml, nonce, timestamp, config), {
        headers: { 'content-type': 'application/xml; charset=utf-8' },
      });
    } catch (err) {
      return new Response(`decrypt error: ${err.message}`, { status: 500 });
    }
  }

  return new Response('Method Not Allowed', { status: 405 });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === '/' || url.pathname === '/health') {
      return new Response('wechat-callback worker ok', {
        headers: { 'content-type': 'text/plain; charset=utf-8' },
      });
    }

    if (url.pathname === '/callback') {
      return handleCallback(request, env);
    }

    return new Response('Not Found', { status: 404 });
  },
};
