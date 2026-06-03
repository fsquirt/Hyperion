/**
 * WebAuthn (Passkey) 前端工具函数
 * 处理 Base64URL 编解码和浏览器 WebAuthn API 调用
 */

function base64UrlToBuffer(base64url) {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const padLen = (4 - base64.length % 4) % 4;
    const padded = base64 + '='.repeat(padLen);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
}

function bufferToBase64Url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * 将服务器返回的 options 转换为浏览器 navigator.credentials.create 需要的格式
 */
function transformCreateOptions(options) {
    return {
        ...options,
        challenge: base64UrlToBuffer(options.challenge),
        user: {
            ...options.user,
            id: base64UrlToBuffer(options.user.id)
        },
        excludeCredentials: (options.excludeCredentials || []).map(c => ({
            ...c,
            id: base64UrlToBuffer(c.id)
        }))
    };
}

/**
 * 将服务器返回的 assertion options 转换为 navigator.credentials.get 需要的格式
 */
function transformGetOptions(options) {
    return {
        ...options,
        challenge: base64UrlToBuffer(options.challenge),
        allowCredentials: (options.allowCredentials || []).map(c => ({
            ...c,
            id: base64UrlToBuffer(c.id)
        }))
    };
}

/**
 * 创建 Passkey（注册）
 */
async function createCredential(options) {
    const transformed = transformCreateOptions(options);
    const credential = await navigator.credentials.create({ publicKey: transformed });

    return {
        id: credential.id,
        rawId: bufferToBase64Url(credential.rawId),
        type: credential.type,
        response: {
            clientDataJSON: bufferToBase64Url(credential.response.clientDataJSON),
            attestationObject: bufferToBase64Url(credential.response.attestationObject)
        }
    };
}

/**
 * 使用 Passkey 认证（登录）
 */
async function getAssertion(options) {
    const transformed = transformGetOptions(options);
    const assertion = await navigator.credentials.get({ publicKey: transformed });

    return {
        id: assertion.id,
        rawId: bufferToBase64Url(assertion.rawId),
        type: assertion.type,
        response: {
            clientDataJSON: bufferToBase64Url(assertion.response.clientDataJSON),
            authenticatorData: bufferToBase64Url(assertion.response.authenticatorData),
            signature: bufferToBase64Url(assertion.response.signature),
            userHandle: assertion.response.userHandle
                ? bufferToBase64Url(assertion.response.userHandle)
                : null
        }
    };
}
