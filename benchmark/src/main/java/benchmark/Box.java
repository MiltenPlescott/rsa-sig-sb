/*
 * rsa-sig-sb:benchmark
 *
 * Copyright (c) 2020, Milten Plescott. All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 */

package benchmark;

/**
 *
 * @author Milten Plescott
 */
public enum Box {

    black("black-box"), silver("silver-box");

    public final String label;

    private Box(String label) {
        this.label = label;
    }

}
