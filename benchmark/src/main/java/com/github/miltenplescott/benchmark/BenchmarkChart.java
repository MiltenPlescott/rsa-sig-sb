/*
 * rsa-sig-sb:benchmark
 *
 * Copyright (c) 2020, Milten Plescott. All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 */

package com.github.miltenplescott.benchmark;

import java.awt.BorderLayout;
import java.util.List;
import javax.swing.JFrame;
import javax.swing.JTabbedPane;
import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.data.category.DefaultCategoryDataset;

/**
 *
 * @author Milten Plescott
 */
final class BenchmarkChart {

    private static final String S4 = " ".repeat(4);

    private DefaultCategoryDataset keygen = new DefaultCategoryDataset();
    private DefaultCategoryDataset sig = new DefaultCategoryDataset();
    private DefaultCategoryDataset ver = new DefaultCategoryDataset();

    BenchmarkChart() {
    }

    void sendData(Box xBox, Algorithm alg, int rsaBits, int hashBits, List<Long> data) {
        double avg = getAverage(data);
        switch (alg) {
            case keygen:
                this.keygen.setValue(avg, xBox.label, "" + rsaBits + "-" + hashBits);
                break;
            case sign:
                this.sig.setValue(avg, xBox.label, "" + rsaBits + "-" + hashBits);
                break;
            case verify:
                this.ver.setValue(avg, xBox.label, "" + rsaBits + "-" + hashBits);
                break;
        }
    }

    void displayChart() {
        JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP, JTabbedPane.WRAP_TAB_LAYOUT);

        JFreeChart chart = ChartFactory.createBarChart("Key generation", "RSA bits - hash bits", "Average runtime in seconds", keygen, PlotOrientation.VERTICAL, true, true, true);
        tabbedPane.add("Key generation", new ChartPanel(chart));

        chart = ChartFactory.createBarChart("Signing", "RSA bits - hash bits", "Average runtime in seconds", sig, PlotOrientation.VERTICAL, true, true, true);
        tabbedPane.add("Signing", new ChartPanel(chart));

        chart = ChartFactory.createBarChart("Verification", "RSA bits - hash bits", "Average runtime in seconds", ver, PlotOrientation.VERTICAL, true, true, true);
        tabbedPane.add("Verification", new ChartPanel(chart));

        JFrame frame = new JFrame();
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setLocationByPlatform(true);
        frame.add(tabbedPane, BorderLayout.CENTER);
        frame.pack();
        frame.setVisible(true);
    }

    void displayData() {
        System.out.println("\n================================================================================");
        System.out.println("AVERAGE DATA IN SECONDS");
        System.out.println("================================================================================");
        System.out.println(S4 + "Key generation runtime");
        printData(Algorithm.keygen, this.keygen);
        System.out.println(S4 + "Signing runtime");
        printData(Algorithm.sign, this.sig);
        System.out.println(S4 + "Verification runtime");
        printData(Algorithm.verify, this.ver);
    }

    void printData(Algorithm alg, DefaultCategoryDataset dcd) {
        System.out.println();
        for (Object boxO : dcd.getRowKeys()) {
            if (boxO instanceof String) {
                String boxS = (String) boxO;
                System.out.println(S4 + S4 + boxS);
                for (Object bitsO : dcd.getColumnKeys()) {
                    if (bitsO instanceof String) {
                        String bitsS = (String) bitsO;
                        System.out.println(S4 + S4 + S4 + bitsS + "\t" + String.format("%.10f", dcd.getValue(boxS, bitsS).doubleValue()));
                    }
                }
            }
        }
        System.out.println();
    }

    private double getAverage(List<Long> data) {
        double avg = data.stream().mapToLong(Long::longValue).average().orElse(0.0);
        return avg / 1_000_000_000d;
    }

}
