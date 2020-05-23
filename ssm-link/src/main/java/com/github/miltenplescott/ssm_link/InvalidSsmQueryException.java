/*
 * rsa-sig-sb:ssm-link
 *
 * Copyright (c) 2020, Milten Plescott. All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 */

package com.github.miltenplescott.ssm_link;

/**
 *
 * @author Milten Plescott
 */
public class InvalidSsmQueryException extends RuntimeException {

    public InvalidSsmQueryException() {
        super("Invalid SSM query!");
    }

}
