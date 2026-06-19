using System.Security.Cryptography;

namespace PhantomAgent.Crypto;

public class AesCipher
{
    private const int KeySize = 32;   // 256-bit
    private const int NonceSize = 12; // 96-bit
    private const int TagSize = 16;   // 128-bit
    private readonly byte[] _key;

    public AesCipher(byte[] key)
    {
        if (key.Length != KeySize)
            throw new ArgumentException($"Key must be {KeySize} bytes, got {key.Length}");
        _key = (byte[])key.Clone();
    }

    // Returns: nonce(12) + ciphertext + tag(16) — byte-compatible with Python agent
    public byte[] Encrypt(byte[] plaintext)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[TagSize];

        using var aes = new AesGcm(_key, TagSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);

        byte[] result = new byte[NonceSize + ciphertext.Length + TagSize];
        Buffer.BlockCopy(nonce, 0, result, 0, NonceSize);
        Buffer.BlockCopy(ciphertext, 0, result, NonceSize, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, result, NonceSize + ciphertext.Length, TagSize);
        return result;
    }

    // Expects: nonce(12) + ciphertext + tag(16)
    public byte[] Decrypt(byte[] data)
    {
        if (data.Length < NonceSize + TagSize)
            throw new ArgumentException("Ciphertext too short");

        byte[] nonce = new byte[NonceSize];
        Buffer.BlockCopy(data, 0, nonce, 0, NonceSize);

        int ctLen = data.Length - NonceSize - TagSize;
        byte[] ciphertext = new byte[ctLen];
        Buffer.BlockCopy(data, NonceSize, ciphertext, 0, ctLen);

        byte[] tag = new byte[TagSize];
        Buffer.BlockCopy(data, NonceSize + ctLen, tag, 0, TagSize);

        byte[] plaintext = new byte[ctLen];
        using var aes = new AesGcm(_key, TagSize);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);
        return plaintext;
    }

    public static byte[] GenerateKey()
    {
        return RandomNumberGenerator.GetBytes(KeySize);
    }
}
