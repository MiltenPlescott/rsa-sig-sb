/*
 * rsa-sig-sb:secure-silver-module
 *
 * Copyright (c) 2020, Milten Plescott. All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 */

package ssm;

import java.math.BigInteger;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import benchmark.BenchmarkService;
import ssm_link.InvalidSsmQueryException;
import ssm_link.SsmLinkService;

/**
 *
 * @author Milten Plescott
 */
class Ssm extends UnicastRemoteObject implements SsmLinkService, BenchmarkService {

    private static Registry reg;

    private int rsaBits;
    private int hashBits;
    private int maxQueries;
    private String provider;

    private final SecureRandom csrng = new SecureRandom();

    private int currentQueries;
    private BigInteger modulusN;
    private List<BigInteger> privateKeyTable;
    private List<BigInteger> publicKeyTable;

    public Ssm() throws RemoteException {
        super();
    }

    public static void main(String[] args) throws RemoteException {
        Ssm ssm = new Ssm();

        if (args.length == 4) {
            try {
                ssm.rsaBits = Integer.parseInt(args[0], 10);
                ssm.hashBits = Integer.parseInt(args[1], 10);
                ssm.maxQueries = Integer.parseInt(args[2], 10);
                ssm.provider = args[3];
                System.out.println("SSM main arguments:");
                System.out.println("    RSA bits: " + ssm.rsaBits);
                System.out.println("    Hash bits: " + ssm.hashBits);
                System.out.println("    Max queries: " + ssm.maxQueries);
                System.out.println("    Provider: " + ssm.provider);
                System.out.println("");
            }
            catch (NumberFormatException ex) {
                System.err.println("Could not parse SSM arguments.");
                System.exit(1);
            }
        }
        else {
            System.err.println("Incorrect number of arguments.");
            System.exit(1);
        }

        System.setProperty("java.rmi.server.hostname", "127.0.0.1");
        String hostname = System.getProperty("java.rmi.server.hostname");
        System.out.println("Hostname: " + hostname);

        System.out.println("Creating registry at port: " + Registry.REGISTRY_PORT);
        reg = LocateRegistry.createRegistry(Registry.REGISTRY_PORT);

        System.out.println("Binding new name: SsmService");
        reg.rebind("SsmService", ssm);

        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            if (!ssm.provider.equals("default")) {
                kpg = KeyPairGenerator.getInstance("RSA", ssm.provider);
            }

            System.out.println();
            System.out.println("Keygen algorithm: " + kpg.getAlgorithm());
            System.out.println("   Provider name: " + kpg.getProvider().getName());
            System.out.println("         Version: " + kpg.getProvider().getVersionStr());
            System.out.println("            Info: " + kpg.getProvider().getInfo());

            System.out.println();
            System.out.println("CSRNG algorithm: " + ssm.csrng.getAlgorithm());
            System.out.println("  Provider name: " + ssm.csrng.getProvider().getName());
            System.out.println("        Version: " + ssm.csrng.getProvider().getVersionStr());
            System.out.println("           Info: " + ssm.csrng.getProvider().getInfo());
            System.out.println();
            System.out.println("SSM is running!");
        }
        catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            Logger.getLogger(Ssm.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    /**
     * Returns an array with SSM parameters in the following format: [rsaBits, hashBits, maxQueries].
     */
    @Override
    public int[] getSsmParameters() throws RemoteException {
        return new int[]{this.rsaBits, this.hashBits, this.maxQueries};
    }

    /**
     * Returns true if the key tables are initialized.
     */
    @Override
    public boolean isInitialized() throws RemoteException {
        if (this.privateKeyTable == null) {
            return false;
        }
        if (this.privateKeyTable.isEmpty()) {
            return false;
        }
        return true;
    }

    @Override
    public void generateNewKey() throws RemoteException {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            if (!this.provider.equals("default")) {
                kpg = KeyPairGenerator.getInstance("RSA", this.provider);
            }
            RSAKeyGenParameterSpec params = new RSAKeyGenParameterSpec(this.rsaBits, RSAKeyGenParameterSpec.F4);

            kpg.initialize(params, this.csrng);

            KeyPair kp = kpg.generateKeyPair();
            System.out.println(this.rsaBits + "-bit RSA keypair generated.");

            RSAPublicKey pubKey = (RSAPublicKey) kp.getPublic();
            RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) kp.getPrivate();

            BigInteger primeP = privKey.getPrimeP();
            BigInteger primeQ = privKey.getPrimeQ();
            BigInteger privExpD = privKey.getPrivateExponent();
            BigInteger pubExpE = pubKey.getPublicExponent();
            this.modulusN = pubKey.getModulus();
            BigInteger phiN = primeP.subtract(BigInteger.ONE).multiply(primeQ.subtract(BigInteger.ONE));

            this.privateKeyTable = new ArrayList<>(hashBits);
            this.publicKeyTable = new ArrayList<>(hashBits);

            for (int i = 0; i < this.hashBits; i++) {
                BigInteger genBint;
                do {
                    genBint = new BigInteger(phiN.bitLength(), this.csrng);
                }
                while (genBint.compareTo(phiN) >= 0 || genBint.compareTo(BigInteger.ZERO) <= 0);

                this.privateKeyTable.add(privExpD.modPow(genBint, phiN));
                this.publicKeyTable.add(pubExpE.modPow(genBint, phiN));
            }

            int sizeBits = 2 * this.hashBits * phiN.bitLength();
            double sizeKiB = (sizeBits / 8) / 1024.0;
            double sizeMiB = sizeKiB / 1024.0;
            if (sizeMiB < 1.0) {
                System.out.println("Size of generated tables: " + String.format("%.1f", sizeKiB) + " KiB\n");
            }
            else {
                System.out.println("Size of generated tables: " + String.format("%.3f", sizeMiB) + " MiB\n");
            }

            this.currentQueries = 0;

            privKey = null;
            kp = null;
            primeP = null;
            primeQ = null;
            privExpD = null;
        }
        catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchProviderException ex) {
            Logger.getLogger(Ssm.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * Deletes keys and sets current number of queries to 0.
     */
    @Override
    public void deleteKeys() throws RemoteException {
        System.out.println("Deleting keys.");
        this.modulusN = null;
        this.privateKeyTable.clear();
        this.privateKeyTable = null;
        this.publicKeyTable.clear();
        this.publicKeyTable = null;
        this.currentQueries = 0;
    }

    @Override
    public BigInteger getModulusN() throws RemoteException, InvalidSsmQueryException {
        if (this.modulusN == null) {
            throw new InvalidSsmQueryException();
        }
        return this.modulusN;
    }

    /*
     * If privateKeyTable is list(a,b,c,d,e)
     * and user requests rows for messageHash = 01011
     * then this method will return list(b,d,e)
     * instead of a list(0,b,0,d,e)
     */
    @Override
    public List<BigInteger> getPrivateKeyTableRows(BigInteger messageHash) throws RemoteException, InvalidSsmQueryException {
        if (this.privateKeyTable == null) {
            throw new InvalidSsmQueryException();
        }
        else if (messageHash == null) {
            throw new InvalidSsmQueryException();
        }
        else if (messageHash.bitCount() <= 0) {
            throw new InvalidSsmQueryException();
        }
        else if (messageHash.bitCount() >= privateKeyTable.size()) {
            throw new InvalidSsmQueryException();
        }
        else if (messageHash.bitLength() > privateKeyTable.size()) {
            throw new InvalidSsmQueryException();
        }
        else if (this.currentQueries == this.maxQueries) {
            System.err.println("Max number of queries reached.");
            deleteKeys();
            throw new InvalidSsmQueryException();
        }
        else if (this.currentQueries > this.maxQueries) {
            throw new AssertionError("This shouldn't be possible.");
        }

        List<BigInteger> retList = new ArrayList<>(messageHash.bitCount());
        for (int i = 0; i < messageHash.bitLength(); i++) {
            if (messageHash.testBit(i)) {
                retList.add(this.privateKeyTable.get(i));
            }
        }

        this.currentQueries++;

        return retList;
    }

    @Override
    public List<BigInteger> getPublicKeyTable() throws RemoteException, InvalidSsmQueryException {
        if (this.publicKeyTable == null) {
            throw new InvalidSsmQueryException();
        }
        else if (this.publicKeyTable.isEmpty()) {
            throw new InvalidSsmQueryException();
        }
        return this.publicKeyTable;
    }

    @Override
    public void debug() throws RemoteException {
        this.rsaBits = 9;
        this.hashBits = 7;
        this.currentQueries = 0;
        this.maxQueries = 100000;
        this.modulusN = BigInteger.valueOf(323);
        // p = 17
        // q = 19
        // e = 59
        // d = 83
        // phi(n) = 288

        this.privateKeyTable = new ArrayList<>();
        this.privateKeyTable.add(BigInteger.valueOf(59));
        this.privateKeyTable.add(BigInteger.valueOf(179));
        this.privateKeyTable.add(BigInteger.valueOf(145));
        this.privateKeyTable.add(BigInteger.valueOf(11));
        this.privateKeyTable.add(BigInteger.valueOf(241));
        this.privateKeyTable.add(BigInteger.valueOf(169));
        this.privateKeyTable.add(BigInteger.valueOf(203));

        this.publicKeyTable = new ArrayList<>();
        this.publicKeyTable.add(BigInteger.valueOf(83));
        this.publicKeyTable.add(BigInteger.valueOf(251));
        this.publicKeyTable.add(BigInteger.valueOf(145));
        this.publicKeyTable.add(BigInteger.valueOf(131));
        this.publicKeyTable.add(BigInteger.valueOf(49));
        this.publicKeyTable.add(BigInteger.valueOf(121));
        this.publicKeyTable.add(BigInteger.valueOf(227));
    }

    @Override
    public void setRsaBits(int rsaBits) throws RemoteException {
        this.rsaBits = rsaBits;
    }

    @Override
    public void setHashBits(int hashBits) throws RemoteException {
        this.hashBits = hashBits;
    }

    @Override
    public void setMaxQueries(int maxQueries) throws RemoteException {
        this.maxQueries = maxQueries;
    }

}
