package io.winty.sec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.security.GeneralSecurityException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class KeyExchangeContextTest {
    
    private KeyExchangeContext bob;
    private KeyExchangeContext alice;
    
    private static final String plainText = "Bolo de Cenoura";
    
    @BeforeEach
    public void initilize() throws GeneralSecurityException{
        alice = new KeyExchangeContext();
    }
    
    @Test
    void keyAgreementTest() throws GeneralSecurityException{
        bob = new KeyExchangeContext();
        // Troca de chaves
        alice.keyAgreement(bob.getPublicKey());
        bob.keyAgreement(alice.getPublicKey());
        
        assertEquals(plainText, alice.decrypt(bob.encrypt(plainText)), "Deverá retornar o mesmo valor após realizar encrypt pelo bob e decrypt pela alice");
    }
    
    @Test
    void keyAgreementNodeJSPublicKey() throws GeneralSecurityException{
        bob = new KeyExchangeContext();
        // Troca de chaves
        bob.keyAgreement("3059301306072a8648ce3d020106082a8648ce3d0301070342000472f0bcc4080ab7999f2c44a783d8ccbfa44414a889f03f0b8d14a00cc130bf7f7ac8adc44b81cfbd6b92d7735a1263b362d6542c36f20304934763b09376217c");
        
        assertNotNull( bob.encrypt(plainText), "Deverá encryptar o valor realizando keyagreement com NodeJS!");
    }
    
    
}

