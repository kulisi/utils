import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

public class AESTools {
    private static final Logger log = LoggerFactory.getLogger(AESTools.class);
    private static final Integer BLOCK_LENGTH = 128;
    private static final Integer IV_LENGTH = 16;

    public AESTools() {
    }

    public static String decrypt(String content, String key) {
        if (content != null && content.length() != 0 && key != null && key.length() != 0) {
            int ivLength = IV_LENGTH;
            byte[] decode = Base64.getDecoder().decode(content);
            if (decode.length <= ivLength) {
                throw new IllegalArgumentException("错误的密文");
            } else {
                byte[] ivBytes = new byte[ivLength];
                byte[] realData = new byte[decode.length - ivLength];
                System.arraycopy(decode, 0, ivBytes, 0, ivLength);
                System.arraycopy(decode, ivLength, realData, 0, decode.length - ivLength);
                return decrypt(Base64.getEncoder().encodeToString(realData), key, ivBytes);
            }
        } else {
            throw new IllegalArgumentException("密文和密钥不能为空");
        }
    }

    public static String decrypt(String content, String key, byte[] iv) {
        return decrypt(content, key, iv, false);
    }

    public static String decrypt(String content, String key, String iv) {
        if (iv != null && iv.getBytes().length >= IV_LENGTH) {
            byte[] ivSeedBytes = iv.getBytes();
            byte[] ivBytes = new byte[16];
            System.arraycopy(ivSeedBytes, 0, ivBytes, 0, 16);
            return decrypt(content, key, ivBytes, false);
        } else {
            throw new IllegalArgumentException("iv长度不能低于16 byte");
        }
    }

    public static String decrypt(String content, String key, byte[] iv, boolean useSecureRandom) {
        if (content != null && content.length() != 0 && key != null && key.length() != 0) {
            try {
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                cipher.init(2, getSecretKey(key, useSecureRandom), ivSpec);
                byte[] result = cipher.doFinal(Base64.getDecoder().decode(content));
                log.info("解密完成");
                return new String(result, "utf-8");
            } catch (Exception var7) {
                log.warn("AES解密失败:{}", var7);
                return null;
            }
        } else {
            throw new IllegalArgumentException("密文和密钥不能为空");
        }
    }

    private static SecretKeySpec getSecretKey(String key, boolean randomKey) {
        try {
            if (randomKey) {
                KeyGenerator kg = null;
                kg = KeyGenerator.getInstance("AES");
                SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
                secureRandom.setSeed(key.getBytes());
                kg.init(BLOCK_LENGTH, secureRandom);
                SecretKey secretKey = kg.generateKey();
                return new SecretKeySpec(secretKey.getEncoded(), "AES");
            } else {
                return new SecretKeySpec(Arrays.copyOf(key.getBytes("utf-8"), 16), "AES");
            }
        } catch (Exception var5) {
            log.warn("AES生成加密秘钥失败:{}", var5);
            throw new RuntimeException("AES生成加密秘钥失败", var5);
        }
    }

    public static void main(String[] args) {
        String body="fu+/vQLvv70Bbu+/vXjvvy82YhiAU4hFx31bUh7oC4q75qlto0cxgDR+FbTNKjBKWx7MhdvBYTJFbov+mLeJbyYfV9iKOp1mOqVRceMd7ryj7m2v0ac/NrfcCs3f14CcqJAY2lwA5i2Ur9CovDF4Px73dlxwisc92dY+C79N8L6DEcwpwVxfNB0kMbsvGaUFtIGtw1V9MxS/rGYRf9EuEsXB0VkbDHloZtmiAc1S00gw/622kF/ttN4dGzUdSO9dTJcQZCcsv/nwrOnhgr9CwpujHVjBwZYCid/J9j0YQdI5dkuk9Dwn9CcYgQsYT3/Wsd4lyZx0IJPVUt6IeYqISJ3Sw4QttX56dAdu6ORgBEen9g5AZ/onvoU9CeCyTCM+CLrCzRoVIvIEcLGVJU9xK4wkZdUGoH64B4hv5rfn6f01RGjUv4AyypyVHtfuA32SJhAbAvBXZ9bLgk5tzbTvHLVY0MW0C1tW/Bm5pqdKaxJAQljdAc1QVD5PVkmV4EVeWDimSK5Ps679IOVM+I0yAT3UK+QjpNnqh73NFhSRj+sH8/xmICOqTvrlJtvj0PrXW5myE8VAOOhSU3EGJx5AYCbgQV4gdw1Qk9nsRGg12ILRMHSSmI9/dEtxPtkgkK6TCtMKGQsCWSlZTdW9W9eMs4tkocfWMyCY+q35jjWqtt5qZ3e9jB9hUHa2uDNhM2vQiVluxc/PMGKzo3ancrKv6Q==";

        // 本例中测试供应商密钥 = 64544A12A1F147A4A6A73534A125836A
        System.out.println(AESTools.decrypt(body, 供应商密钥));
    }
}
