import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';

// ===================== 北京时间函数 (UTC+8) ===================== //
function getBeijingTimestamp() {
  // 8*3600 = 28800秒 (UTC+8)
  return String(Math.floor(Date.now() / 1000) + 28800);
}
// ============================================================= //

function requireEnv(env, name) {
  const value = env[name];
  if (!value) throw new Error(`Missing environment variable: ${name}`);
  return value;
}

function getConfig(env) {
  const token = requireEnv(env, 'WECHAT_TOKEN');
  const encodingAesKey = requireEnv(env, 'WECHAT_ENCODING_AES_KEY');
  const corpId = requireEnv(env, 'WECHAT_CORP_ID');

  console.log("配置加载成功（部分隐藏）:", {
    token: token.substring(0, 2) + "​***​" + token.substring(token.length - 2),
    encodingAesKey: encodingAesKey.substring(0, 2) + "​***​" + encodingAesKey.substring(encodingAesKey.length - 2),
    corpId: corpId.substring(0, 2) + "​***​" + corpId.substring(corpId.length - 2)
  });

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
  const computedSignature = sha1(raw);
  
  console.log("签名验证参数:", {
    token: token.substring(0, 2) + "​***​",
    timestamp,
    nonce,
    encrypt: encrypt.substring(0, 10) + "..." + encrypt.substring(encrypt.length - 5)
  });
  
  console.log("计算签名:", computedSignature);
  console.log("接收签名:", signature);
  
  return computedSignature === signature;
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
  try {
    const config = getConfig(env);
    const url = new URL(request.url);
    const signature = url.searchParams.get('msg_signature');
    
    // ============== 使用北京时间 (UTC+8) ============== //
    const timestamp = url.searchParams.get('timestamp') || getBeijingTimestamp();
    // ================================================ //
    
    const nonce = url.searchParams.get('nonce') || randomBytes(8).toString('hex');

    console.log("请求方法:", request.method);
    console.log("请求路径:", url.pathname);
    console.log("北京时间戳:", timestamp, 
               "ISO格式:", new Date(parseInt(timestamp) * 1000).toISOString());
    console.log("请求参数:", {
      signature: signature ? signature.substring(0, 5) + "..." : "null",
      nonce: nonce.substring(0, 3) + "..."
    });

    // 时间戳检查
    const serverTime = parseInt(timestamp);
    const clientTime = url.searchParams.get('timestamp') ? 
                      parseInt(url.searchParams.get('timestamp')) : serverTime;
    const timeDiff = Math.abs(serverTime - clientTime);
    console.log(`时间差: ${timeDiff}秒`);
    if (timeDiff > 7200) {
      console.warn("⚠️ 时间差超过2小时，可能验证失败");
    }

    if (request.method === 'GET') {
      const echostr = url.searchParams.get('echostr');
      console.log("GET 验证 echostr:", echostr ? echostr.substring(0, 10) + "..." : "undefined");
      
      if (!signature || !timestamp || !nonce || !echostr) {
        return new Response('Missing required query parameters', { status: 400 });
      }
      
      if (!checkSignature(config.token, signature, timestamp, nonce, echostr)) {
        return new Response('signature error', { status: 403 });
      }

      try {
        const decrypted = decryptMsg(echostr, config);
        console.log("✅ 解密成功:", decrypted);
        return new Response(decrypted, {
          headers: { 'content-type': 'text/plain; charset=utf-8' },
        });
      } catch (err) {
        console.error("❌ 解密失败:", err.message);
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

        console.log(`📩 解密后消息类型: ${msgType}, 内容: ${content.substring(0, 20)}${content.length > 20 ? '...' : ''}`);

        const replyXml = `<xml>
  <ToUserName><![CDATA[${cdata(fromUserName)}]]></ToUserName>
  <FromUserName><![CDATA[${cdata(toUserName)}]]></FromUserName>
  <CreateTime>${getBeijingTimestamp()}</CreateTime>
  <MsgType><![CDATA[text]]></MsgType>
  <Content><![CDATA[收到你的消息: ${cdata(content)}]]></Content>
</xml>`;

        console.log("📤 回复内容:", `收到你的消息: ${content.substring(0, 10)}...`);
        return new Response(encryptMsg(replyXml, nonce, timestamp, config), {
          headers: { 'content-type': 'application/xml; charset=utf-8' },
        });
      } catch (err) {
        console.error("❌ 消息处理失败:", err.message);
        return new Response(`decrypt error: ${err.message}`, { status: 500 });
      }
    }

    return new Response('Method Not Allowed', { status: 405 });
  } catch (err) {
    console.error("🔥 全局错误:", err.stack);
    return new Response(`Server error: ${err.message}`, { status: 500 });
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === '/' || url.pathname === '/health') {
      return new Response('wechat-callback worker ok', {
        headers: { 'content-type': 'text/plain; charset=utf-8' },
      });
    }
    
    // 添加时间检查端点
    if (url.pathname === '/time-check') {
      return new Response(JSON.stringify({
        beijing_timestamp: getBeijingTimestamp(),
        utc_timestamp: Math.floor(Date.now() / 1000),
        iso_beijing: new Date(parseInt(getBeijingTimestamp()) * 1000).toISOString(),
        iso_utc: new Date().toISOString(),
        message: "Worker is using UTC+8 (Beijing Time)"
      }, null, 2), {
        headers: { 'content-type': 'application/json; charset=utf-8' }
      });
    }

    if (url.pathname === '/callback') {
      return handleCallback(request, env);
    }

    return new Response('Not Found', { status: 404 });
  },
};
