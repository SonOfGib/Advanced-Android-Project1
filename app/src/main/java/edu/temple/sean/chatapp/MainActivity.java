package edu.temple.sean.chatapp;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.IBinder;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;

public class MainActivity extends AppCompatActivity {

    KeyService mKeyService;
    boolean mBounded;
    boolean mKeysGenerated;
    KeyPair keys;
    Context mContext;
    static final String DEBUG_USER = "debug";
    String mEncodedString;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Intent mIntent = new Intent(this, KeyService.class);
        bindService(mIntent, mConnection, BIND_AUTO_CREATE);
        mContext = this;
        setContentView(R.layout.activity_main);

        Button keyGenButton = findViewById(R.id.genKeysBtn);
        keyGenButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                keys = mKeyService.getMyKeyPair();
                if(keys != null)
                    mKeysGenerated = true;
                RSAPublicKey publicKey = (RSAPublicKey) keys.getPublic();
                mKeyService.storePublicKey(DEBUG_USER, publicKey.getPublicExponent().toString());
                //Toast.makeText(mContext, "Keys generated", Toast.LENGTH_SHORT).show();
            }
        });

        Button encryptButton = findViewById(R.id.encryptBtn);
        encryptButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                EditText plainTextField =  findViewById(R.id.plainTextField);
                String encodedString = mKeyService.encrypt(plainTextField.getText().toString(),DEBUG_USER);
                TextView cipherTextView = findViewById(R.id.cipherTextView);
                cipherTextView.setText(encodedString);
                mEncodedString = encodedString;
            }
        });

        Button decryptButton = findViewById(R.id.decryptBtn);
        decryptButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String plainString = mKeyService.decrypt(mEncodedString);
                TextView cipherTextView = findViewById(R.id.cipherTextView);
                cipherTextView.setText(plainString);

            }
        });

    }

    @Override
    protected void onStart() {
        super.onStart();

        Intent mIntent = new Intent(this, KeyService.class);
        bindService(mIntent, mConnection, BIND_AUTO_CREATE);
    };

    ServiceConnection mConnection = new ServiceConnection() {
        @Override
        public void onServiceDisconnected(ComponentName name) {
            mBounded = false;
            mKeyService = null;
        }

        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            mBounded = true;
            KeyService.LocalBinder mLocalBinder = (KeyService.LocalBinder)service;
            mKeyService = mLocalBinder.getService();
        }
    };

    @Override
    protected void onStop() {
        super.onStop();
        if(mBounded) {
            unbindService(mConnection);
            mBounded = false;
        }
    };
}
