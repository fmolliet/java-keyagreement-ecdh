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
    
    //@Test
    void keyAgreementNodeJSPublicKey() throws GeneralSecurityException{
        bob = new KeyExchangeContext();
        // Troca de chaves
        bob.keyAgreement("041F22957183AF9807A29D5E99B31A3230CF8081AFF3D87CB014EE44C92B5CAD5FF1B9AB7D824920CB41C65E64316FDECE5D594BA33BEBBBB019B449AB56CA6F33");
        
        assertNotNull( bob.encrypt(plainText), "Deverá encryptar o valor realizando keyagreement com NodeJS!");
    }
    
    
}

