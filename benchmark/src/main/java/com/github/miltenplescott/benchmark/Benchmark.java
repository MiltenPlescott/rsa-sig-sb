/*
 * rsa-sig-sb:benchmark
 *
 * Copyright (c) 2020, Milten Plescott. All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 */

package com.github.miltenplescott.benchmark;

import java.math.BigInteger;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.github.miltenplescott.cpu.Cpu;

/**
 *
 * @author Milten Plescott
 */
final class Benchmark {

    private static final Random RND = new Random();
    private static final String S4 = " ".repeat(4);

    private BenchmarkService service;

    private int matrixLimit;
    private int keys;
    private int messages;

    private final List<List<Integer>> matrix = new ArrayList<>(); // [0] - RSA bits, [1] - hash bits
    private boolean runBB;

    private Cpu cpu;
    private BlackBoxRsa bb;
    private BenchmarkChart chart;

    private Benchmark() {
    }

    public static void main(String[] args) throws RemoteException {
        Benchmark bench = new Benchmark();
        bench.connectToSsm();
        bench.cpu = new Cpu();
        bench.cpu.connectToSsm();

        if (args.length == 3) {
            switch (args[0]) {
                case "short":
                    bench.matrixLimit = 3;
                    bench.keys = 1;
                    bench.messages = 1;
                    break;
                case "medium":
                    bench.matrixLimit = 5;
                    bench.keys = 5;
                    bench.messages = 10;
                    break;
                case "long":
                    bench.matrixLimit = 7;
                    bench.keys = 10;
                    bench.messages = 20;
                    break;
                default:
                    System.err.println("Unrecognized benchmark argument. Choose short, medium or long.");
                    System.exit(1);
                    break;
            }

            String kpgProvider = args[1];
            String signatureProvider = args[2];

            bench.bb = new BlackBoxRsa(kpgProvider, signatureProvider);

            System.out.println("Benchmark settings for every RSA_BITS-HASH_BITS pair:");
            System.out.println("\tnumber of keys: " + bench.keys);
            System.out.println("\tnumber of messages: " + bench.messages);

            try {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                if (!kpgProvider.equals("default")) {
                    kpg = KeyPairGenerator.getInstance("RSA", kpgProvider);
                }

                System.out.println();
                System.out.println();
                System.out.println("BLACK-BOX parameters");
                System.out.println();
                System.out.println(S4 + "Keygen algorithm: " + kpg.getAlgorithm());
                System.out.println(S4 + "   Provider name: " + kpg.getProvider().getName());
                System.out.println(S4 + "         Version: " + kpg.getProvider().getVersionStr());
                System.out.println(S4 + "            Info: " + kpg.getProvider().getInfo());

                Signature signature = Signature.getInstance("SHA256withRSA");
                if (!signatureProvider.equals("default")) {
                    signature = Signature.getInstance("SHA256withRSA", signatureProvider);
                }

                System.out.println();
                System.out.println(S4 + "Signature algorithm: " + signature.getAlgorithm());
                System.out.println(S4 + "      Provider name: " + signature.getProvider().getName());
                System.out.println(S4 + "            Version: " + signature.getProvider().getVersionStr());
                System.out.println(S4 + "               Info: " + signature.getProvider().getInfo());
                System.out.println();
            }
            catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
                Logger.getLogger(Benchmark.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        else {
            System.err.println("Incorrect number of arguments.");
            System.exit(1);
        }

        bench.chart = new BenchmarkChart();
        bench.runBenchmark();
        bench.chart.displayChart();
        bench.chart.displayData();
    }

    private void runBenchmark() throws RemoteException {
        this.initMatrix();
        this.service.setMaxQueries(Integer.MAX_VALUE); // so benchmark won't get interrupted
        System.out.println("================================================================================");
        System.out.println("Starting benchmark!");
        for (int i = 0; i < this.matrixLimit; i++) {
            System.out.println("================================================================================");
            System.out.println(" RSA bits: " + this.matrix.get(i).get(0) + " (kappa) (SSM, black-box)");
            System.out.println("Hash bits: " + this.matrix.get(i).get(1) + " (lambda) (SSM)");
            if (Objects.equals(this.matrix.get(i).get(0), this.matrix.get(i).get(1))) {
                this.runBB = true;
            }
            else {
                this.runBB = false;
                System.out.println("Skipping black-box.");
            }

            this.runKeys(this.matrix.get(i).get(0), this.matrix.get(i).get(1));
        }
    }

    private void runKeys(int rsaBits, int hashBits) throws RemoteException {
        this.service.setRsaBits(rsaBits);
        this.service.setHashBits(hashBits);

        List<Long> black = new ArrayList<>();
        List<Long> silver = new ArrayList<>();

        for (int i = 0; i < this.keys; i++) {

            if (this.runBB) {
                long start = System.nanoTime();
                this.bb.generateKey(rsaBits);
                long end = System.nanoTime() - start;
                black.add(end);
                System.out.println("");
                System.out.println("--------------------------------------------------------------------------------");
                System.out.println(S4 + "Time to generate black-box keypair (s): " + String.format("%.4f", end / 1_000_000_000d));
            }

            long start = System.nanoTime();
            service.generateNewKey();
            long end = System.nanoTime() - start;
            silver.add(end);
            System.out.println(S4 + "Time to generate SSM keypair and tables (s): " + String.format("%.4f", end / 1_000_000_000d));
            System.out.println("--------------------------------------------------------------------------------");

            this.runMessages(rsaBits, hashBits);
        }
        this.chart.sendData(Box.black, Algorithm.keygen, rsaBits, hashBits, black);
        this.chart.sendData(Box.silver, Algorithm.keygen, rsaBits, hashBits, silver);
    }

    private void runMessages(int rsaBits, int hashBits) throws RemoteException {
        List<Long> blackSig = new ArrayList<>();
        List<Long> blackVer = new ArrayList<>();
        List<Long> silverSig = new ArrayList<>();
        List<Long> silverVer = new ArrayList<>();

        for (int i = 0; i < this.messages; i++) {
            String message = Long.toString(RND.nextLong());
            System.out.println("\n" + S4 + S4 + "Message " + (i + 1) + "/" + this.messages + ": \"" + message + "\"");

            if (this.runBB) {
                long signStartBB = System.nanoTime();
                byte[] signature = this.bb.sign(message);
                long signEndBB = System.nanoTime() - signStartBB;
                blackSig.add(signEndBB);

                long verifyStartBB = System.nanoTime();
                this.bb.verify(message, signature);
                long verifyEndBB = System.nanoTime() - verifyStartBB;
                blackVer.add(verifyEndBB);

                System.out.println(S4 + S4 + S4 + "Time to sign using black-box SHA256withRSA (s): " + String.format("%.4f", signEndBB / 1_000_000_000d));
                System.out.println(S4 + S4 + S4 + "Time to verify using black-box SHA256withRSA (s): " + String.format("%.4f", verifyEndBB / 1_000_000_000d));
            }

            long signStartSB = System.nanoTime();
            BigInteger signature = this.cpu.sign(message);
            long signEndSB = System.nanoTime() - signStartSB;
            silverSig.add(signEndSB);

            long verifyStartSB = System.nanoTime();
            this.cpu.verify(message, signature);
            long verifyEndSB = System.nanoTime() - verifyStartSB;
            silverVer.add(verifyEndSB);

            System.out.println(S4 + S4 + S4 + "Time to sign using SSM (s): " + String.format("%.4f", signEndSB / 1_000_000_000d));
            System.out.println(S4 + S4 + S4 + "Time to verify using SSM (s): " + String.format("%.4f", verifyEndSB / 1_000_000_000d));
        }
        this.chart.sendData(Box.black, Algorithm.sign, rsaBits, hashBits, blackSig);
        this.chart.sendData(Box.black, Algorithm.verify, rsaBits, hashBits, blackVer);
        this.chart.sendData(Box.silver, Algorithm.sign, rsaBits, hashBits, silverSig);
        this.chart.sendData(Box.silver, Algorithm.verify, rsaBits, hashBits, silverVer);
    }

    private void initMatrix() {
        this.matrix.add(Arrays.asList(512, 512));
        this.matrix.add(Arrays.asList(512, 1024));
        this.matrix.add(Arrays.asList(1024, 1024));
        this.matrix.add(Arrays.asList(1024, 2048));
        this.matrix.add(Arrays.asList(2048, 2048));
        this.matrix.add(Arrays.asList(2048, 4096));
        this.matrix.add(Arrays.asList(4096, 4096));
    }

    private void connectToSsm() {
        try {
            Registry reg = LocateRegistry.getRegistry("127.0.0.1", 1099);
            this.service = (BenchmarkService) reg.lookup("SsmService");
        }
        catch (RemoteException | NotBoundException ex) {
            Logger.getLogger(Benchmark.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

}
