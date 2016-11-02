package yu.encode;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import static yu.encode.Des.generateKey;

public class MainActivity extends AppCompatActivity {
    private String data = "this is a test data";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Log.e("TAG", "原始数据 ---->" + data);

        String aesKey = generateKey();
        String encryStr = Aes.encrypt(aesKey, data);
        Log.e("TAG", "AES加密后json数据 ---->" + encryStr);
        String decryStr = Aes.decrypt(aesKey, encryStr);
        Log.e("TAG", "AES解密后json数据 ---->" + decryStr);


        String desKey = generateKey();
        String enDes = Des.encode(desKey, data);
//        Log.e("TAG", "DES加密后json数据 ---->" + enDes);
//        String deDes = Des.decode(desKey, enDes);
//        Log.e("TAG", "DES解密后json数据 ---->" + deDes);

//        try {
//            RSAPublicKey rsaKey = Rsa.loadPublicKey(getAssets().open("rsa_public_key.pem"));
//            String encrptAes = Rsa.encryptByPublicKey(aesKey, rsaKey);
//            Log.e("TAG", "RSA加密AES ---->" + encrptAes);
//            Log.e("TAG", "AES加密数据 ---->" + encryStr);
//            RSAPrivateKey rsaPrivateKey = Rsa.loadPrivateKey(getAssets().open("pkcs8_rsa_private_key.pem"));
//            String decryptAes = Rsa.decryptByPrivateKey(aesKey, rsaPrivateKey);
//            Log.e("TAG", "RSA解密AES ---->" + decryptAes);
//            String content = Aes.decrypt(aesKey, encryStr);
//            Log.e("TAG", "AES解密数据 ---->" + content);
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
        try {
            RSAPublicKey rsaKey = Rsa.loadPublicKey(getAssets().open("rsa_public_key.pem"));
            String encrptAes = Rsa.encryptByPublicKey(desKey, rsaKey);
            Log.e("TAG", "RSA加密DES ---->" + encrptAes);
            Log.e("TAG", "DES加密数据 ---->" + enDes);
            RSAPrivateKey rsaPrivateKey = Rsa.loadPrivateKey(getAssets().open("pkcs8_rsa_private_key.pem"));
            String decryptAes = Rsa.decryptByPrivateKey(desKey, rsaPrivateKey);
            Log.e("TAG", "RSA解密DES ---->" + decryptAes);
            String content = Des.decode(desKey, enDes);
            Log.e("TAG", "DES解密数据 ---->" + content);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
