/*
 * rsa-sig-sb:benchmark
 *
 * Copyright (c) 2020, Milten Plescott. All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 */

package com.github.miltenplescott.benchmark;

import java.rmi.Remote;
import java.rmi.RemoteException;

/**
 *
 * @author Milten Plescott
 */
public interface BenchmarkService extends Remote {

    void setRsaBits(int rsaBits) throws RemoteException;

    void setHashBits(int hashBits) throws RemoteException;

    void setMaxQueries(int maxQueries) throws RemoteException;

    void generateNewKey() throws RemoteException;

    void debug() throws RemoteException;

}
