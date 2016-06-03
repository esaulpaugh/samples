package samples.esaulpaugh.encryptednotepad;

import android.app.Application;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.NoSuchPaddingException;

/**
 * Created by esaulpaugh on 3/21/16.
 */
public class CustomApplication extends Application {

    private EncryptionManager encryptionManager;

    @Override
    public void onCreate() {
        super.onCreate();
//
//        String salt = KeyUtils.getSalt(getApplicationContext());
//
//        try {
//            this.encryptionManager = new EncryptionManager(getApplicationContext(), "yee", salt);
//        } catch (NoSuchAlgorithmException e) {
//            e.printStackTrace();
//        } catch (InvalidKeyException e) {
//            e.printStackTrace();
//        } catch (NoSuchPaddingException e) {
//            e.printStackTrace();
//        } catch (CertificateException e) {
//            e.printStackTrace();
//        } catch (UnrecoverableEntryException e) {
//            e.printStackTrace();
//        } catch (KeyStoreException e) {
//            e.printStackTrace();
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
    }

    public void setEncryptionManager(EncryptionManager encryptionManager) {
        this.encryptionManager = encryptionManager;
    }

    public EncryptionManager getEncryptionManager() {
        return encryptionManager;
    }

}
