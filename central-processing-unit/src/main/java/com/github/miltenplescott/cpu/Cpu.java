/*
 * rsa-sig-sb:central-processing-unit
 *
 * Copyright (c) 2020, Milten Plescott. All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 */

package com.github.miltenplescott.cpu;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.crypto.digests.SHAKEDigest;

import com.github.miltenplescott.ssm_link.InvalidSsmQueryException;
import com.github.miltenplescott.ssm_link.SsmLinkService;

/**
 *
 * @author Milten Plescott
 */
public final class Cpu {

    private static int rsaBits;
    private static int hashBits;
    private static int maxQueries;

    private SsmLinkService service;

    public Cpu() {
    }

    /*
     * because of circular dependency, running CPU requires:
     *   a) to remove :benchmark dependency from ssm build script
     *   b) to remove BenchmarkService interface implementation from Ssm
     */
    public static void main(String[] args) throws RemoteException {
//        Cpu cpu = new Cpu();
//        cpu.connectToSsm();
//        cpu.loadParameters();
//        cpu.exampleUsage();
    }

    public void connectToSsm() {
        try {
            Registry reg = LocateRegistry.getRegistry("127.0.0.1", 1099);
            this.service = (SsmLinkService) reg.lookup("SsmService");
        }
        catch (RemoteException | NotBoundException ex) {
            Logger.getLogger(Cpu.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private void loadParameters() throws RemoteException {
        int[] params = this.service.getSsmParameters();
        rsaBits = params[0];
        hashBits = params[1];
        maxQueries = params[2];

        System.out.println("Received SSM parameters:");
        System.out.println("    rsaBits: " + rsaBits);
        System.out.println("    hashBits: " + hashBits);
        System.out.println("    maxQueries: " + maxQueries);
    }

    private void exampleUsage() throws RemoteException {
        if (!this.service.isInitialized()) {
            this.service.generateNewKey();
        }
        String message = "message";
        System.out.println("Signing message: \"" + message + "\"");
        BigInteger signature = sign(message);
        System.out.println("Signature: " + signature.toString(16));
        verify(message, signature);
    }

    public BigInteger sign(String message) throws RemoteException {
        BigInteger hashBint = hashAndBint(message);
        BigInteger signature = hashBint;

        try {
            List<BigInteger> privKeyRows = this.service.getPrivateKeyTableRows(hashBint);
            BigInteger modN = this.service.getModulusN();
            signature = signature.mod(modN);
            for (BigInteger d : privKeyRows) {
                signature = signature.modPow(d, modN);
            }
        }
        catch (InvalidSsmQueryException ex) {
            Logger.getLogger(Cpu.class.getName()).log(Level.SEVERE, null, ex);
        }

        return signature;
    }

    public void verify(String message, BigInteger signature) throws RemoteException {
        BigInteger hashBint = hashAndBint(message);

        try {
            List<BigInteger> pubTable = this.service.getPublicKeyTable();
            BigInteger modN = this.service.getModulusN();
            for (int i = 0; i < hashBint.bitLength(); i++) {
                if (hashBint.testBit(i)) {
                    signature = signature.modPow(pubTable.get(i), modN);
                }
            }

            if (hashBint.mod(modN).equals(signature)) {
                System.out.println("    Signature successfully verified!");
            }
            else {
                System.out.println("Signature is invalid!");
                throw new AssertionError();
            }

        }
        catch (InvalidSsmQueryException ex) {
            Logger.getLogger(Cpu.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private BigInteger hashAndBint(String message) throws RemoteException {
        byte[] hashArray = hashMessage(message);
        return new BigInteger(1, hashArray);
    }

    private byte[] hashMessage(String message) throws RemoteException {
        int hashOutputLength = this.service.getSsmParameters()[1];
        if (hashOutputLength % 8 != 0) {
            System.err.println("Invalid choice of hash bits! Choose a multiple of 8.");
            System.exit(1);
        }
        int hashBytes = hashOutputLength / 8;
        byte[] msgArray = message.getBytes(StandardCharsets.UTF_8);
        byte[] hashArray = new byte[hashBytes];

        SHAKEDigest shake = new SHAKEDigest(256);
        shake.update(msgArray, 0, msgArray.length);
        int bytesWritten = shake.doFinal(hashArray, 0, hashBytes);

        if (hashBytes != bytesWritten) {
            System.err.println("Unexpected SHAKE output.");
        }

        return hashArray;
    }

}
