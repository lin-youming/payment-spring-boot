/*
 *  Copyright 2019-2022 felord.cn
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *       https://www.apache.org/licenses/LICENSE-2.0
 *  Website:
 *       https://felord.cn
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package cn.felord.payment.wechat.v3;


import cn.felord.payment.PayException;
import org.springframework.core.io.Resource;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * 证书工具
 *
 * @author felord.cn
 * @since 1.0.0.RELEASE
 */
public class KeyPairFactory {
    private static final String CERT_ALIAS = "Tenpay Certificate";
//    private static final KeyStore PKCS12_KEY_STORE;

/*    static {
        try {
            PKCS12_KEY_STORE = KeyStore.getInstance("PKCS12");
        } catch (KeyStoreException e) {
            throw new PayException(" wechat pay keystore initialization failed");
        }
    }*/

    public WechatMetaBean initWechatMetaBean(String pemContent, String keyPemContent, String keyPass) {
        return this.initWechatMetaBean(pemContent, keyPemContent, CERT_ALIAS, keyPass);
    }

    /**
     * 获取公私钥.
     *
     * @param keyAlias the key alias
     * @param keyPass  password
     * @return the key pair
     */
    public WechatMetaBean initWechatMetaBean(String certPemContent, String keyPemContent, String keyAlias, String keyPass) {
        try {

            // 提取证书
            X509Certificate certificate = null;
            int beginCertIndex = certPemContent.indexOf("-----BEGIN CERTIFICATE-----");
            int endCertIndex = certPemContent.indexOf("-----END CERTIFICATE-----", beginCertIndex);
            if (beginCertIndex >= 0 && endCertIndex > beginCertIndex) {
                String base64Cert = certPemContent.substring(beginCertIndex + "-----BEGIN CERTIFICATE-----".length(), endCertIndex)
                        .replaceAll("\\s", ""); // 移除所有空白字符
                if (isValidBase64(base64Cert)) {
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(base64Cert)));
                } else {
                    throw new PayException("Invalid Base64 encoding in the certificate.");
                }
            }

            // 提取私钥
            PrivateKey privateKey = null;
            int beginKeyIndex = keyPemContent.indexOf("-----BEGIN PRIVATE KEY-----");
            int endKeyIndex = keyPemContent.indexOf("-----END PRIVATE KEY-----", beginKeyIndex);
            if (beginKeyIndex >= 0 && endKeyIndex > beginKeyIndex) {
                String base64Key = keyPemContent.substring(beginKeyIndex + "-----BEGIN PRIVATE KEY-----".length(), endKeyIndex)
                        .replaceAll("\\s", ""); // 移除所有空白字符
                if (isValidBase64(base64Key)) {
                    byte[] decodedKey = Base64.getDecoder().decode(base64Key);
                    KeyFactory kf = KeyFactory.getInstance("RSA"); // 假设是 RSA 密钥
                    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
                    privateKey = kf.generatePrivate(keySpec);
                } else {
                    throw new PayException("Invalid Base64 encoding in the private key.");
                }
            }

            // 检查证书有效性
            if (certificate != null) {
                certificate.checkValidity();
            } else {
                throw new PayException("No valid certificate found in the provided PEM file.");
            }

            // 设置 WechatMetaBean
            WechatMetaBean wechatMetaBean = new WechatMetaBean();
            wechatMetaBean.setKeyPair(new KeyPair(certificate.getPublicKey(), privateKey));
            wechatMetaBean.setSerialNumber(certificate.getSerialNumber().toString(16).toUpperCase());
            return wechatMetaBean;
        } catch (GeneralSecurityException e) {
            throw new PayException("Cannot load keys from store: ", e);
        }
    }

    private boolean isValidBase64(String base64String) {
        try {
            Base64.getDecoder().decode(base64String);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
