/*
 * rsa-sig-sb:benchmark
 *
 * Copyright (c) 2020, Milten Plescott. All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 */

package com.github.miltenplescott.benchmark;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Milten Plescott
 */
final class BlackBoxRsa {

    private SecureRandom csrng = new SecureRandom();
    private String kpgProvider;
    private String signatureProvider;

    private KeyPair kp;

    BlackBoxRsa(String kpgProvider, String signatureProvider) {
        this.kpgProvider = kpgProvider;
        this.signatureProvider = signatureProvider;
    }

    void generateKey(int rsaBits) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            if (!kpgProvider.equals("default")) {
                kpg = KeyPairGenerator.getInstance("RSA", kpgProvider);
            }
            RSAKeyGenParameterSpec params = new RSAKeyGenParameterSpec(rsaBits, RSAKeyGenParameterSpec.F4);
            kpg.initialize(params, csrng);
            kp = kpg.generateKeyPair();
        }
        catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchProviderException ex) {
            Logger.getLogger(BlackBoxRsa.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    byte[] sign(String message) {
        try {
            Signature sig = Signature.getInstance("SHA256withRSA");
            if (!signatureProvider.equals("default")) {
                sig = Signature.getInstance("SHA256withRSA", signatureProvider);
            }

            sig.initSign(kp.getPrivate(), csrng);
            sig.update(message.getBytes(StandardCharsets.UTF_8));
            return sig.sign();
        }
        catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | SignatureException ex) {
            Logger.getLogger(BlackBoxRsa.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
    }

    void verify(String message, byte[] signature) {
        try {
            Signature ver = Signature.getInstance("SHA256withRSA");
            if (!signatureProvider.equals("default")) {
                ver = Signature.getInstance("SHA256withRSA", signatureProvider);
            }

            ver.initVerify(kp.getPublic());
            ver.update(message.getBytes(StandardCharsets.UTF_8));
            if (ver.verify(signature)) {
                System.out.println("    Signature successfully verified!");
            }
            else {
                System.out.println("Signature is invalid!");
                throw new AssertionError();
            }
        }
        catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | SignatureException ex) {
            Logger.getLogger(BlackBoxRsa.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

}
