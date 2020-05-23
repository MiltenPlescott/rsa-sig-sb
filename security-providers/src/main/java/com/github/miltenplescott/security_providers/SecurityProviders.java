/*
 * rsa-sig-sb:security-providers
 *
 * Copyright (c) 2020, Milten Plescott. All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 */

package com.github.miltenplescott.security_providers;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.security.Provider.Service;

/**
 *
 * @author Milten Plescott
 */

final class SecurityProviders {

    private SecurityProviders() {
        throw new AssertionError("Suppress default constructor for noninstantiability.");
    }

    public static void main(String[] args) {
        Set<Provider> kpgProviderSet = new HashSet<>();
        Set<Provider> signatureProviderSet = new HashSet<>();

        Provider[] providers = Security.getProviders();
        for (Provider provider : providers) {
            Set<Service> services = provider.getServices();
            for (Service service : services) {
                if (service.getType().equals("KeyPairGenerator") && service.getAlgorithm().equals("RSA")) {
                    kpgProviderSet.add(provider);
                }
                if (service.getType().equals("Signature") && service.getAlgorithm().equals("SHA256withRSA")) {
                    signatureProviderSet.add(provider);
                }
            }
        }

        System.out.println();
        System.out.println("PROVIDERS FOR RSA KEY PAIR GENERATOR");
        System.out.println();

        for (Provider provider : kpgProviderSet) {
            System.out.println("================================================================================");
            System.out.println("Provider name (ID): " + provider.getName());
            System.out.println("Provider version: " + provider.getVersionStr());
            System.out.println("Provider info: " + provider.getInfo());

            SecureRandom csrng = new SecureRandom();
            List<Integer> keySizeList = new ArrayList<>();

            for (int exp = 1; exp <= 25; exp++) {
                keySizeList.add((int) Math.pow(2, exp));
            }
            List<Integer> supportedKeySizes = new ArrayList<>(keySizeList);

            for (int keySize : keySizeList) {
                try {
                    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                    RSAKeyGenParameterSpec params = new RSAKeyGenParameterSpec(keySize, RSAKeyGenParameterSpec.F4);
                    kpg.initialize(params, csrng);
                }
                catch (InvalidAlgorithmParameterException ex) {
                    supportedKeySizes.remove((Integer) keySize);
                }
                catch (NoSuchAlgorithmException ex) {
                    Logger.getLogger(SecurityProviders.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
            System.out.println("Supported power of 2 key sizes: " + supportedKeySizes);
        }
        System.out.println("================================================================================");

        System.out.println();
        System.out.println();
        System.out.println();
        System.out.println("PROVIDERS FOR BLACK-BOX SHA256withRSA SIGNATURE ALGORITHM");
        System.out.println();

        for (Provider provider : signatureProviderSet) {
            System.out.println("================================================================================");
            System.out.println("Provider name (ID): " + provider.getName());
            System.out.println("Provider version: " + provider.getVersionStr());
            System.out.println("Provider info: " + provider.getInfo());
        }
        System.out.println("================================================================================");
    }

}
