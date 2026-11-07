"""三套可互换的认证加密入口；均接受 bytes，输出密文与 16 字节认证标签。

aes_gcm: AES-256-GCM，12 字节 nonce。
chacha20_poly1305: ChaCha20-Poly1305，12 字节 nonce。
xchacha20_poly1305: XChaCha20-Poly1305，24 字节 nonce。
后两套共享 _chacha 中的算术实现；这里不派生密钥、不生成随机数、不读写文件。
"""
