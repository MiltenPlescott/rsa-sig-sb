/*
 * rsa-sig-sb:ssm-link
 *
 * Copyright (c) 2020, Milten Plescott. All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 */

package com.github.miltenplescott.ssm_link;

import java.math.BigInteger;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.util.List;

/**
 *
 * @author Milten Plescott
 */
public interface SsmLinkService extends Remote {

    int[] getSsmParameters() throws RemoteException;

    boolean isInitialized() throws RemoteException;

    void generateNewKey() throws RemoteException;

    void deleteKeys() throws RemoteException;

    BigInteger getModulusN() throws RemoteException, InvalidSsmQueryException;

    List<BigInteger> getPrivateKeyTableRows(BigInteger messageHash) throws RemoteException, InvalidSsmQueryException;

    List<BigInteger> getPublicKeyTable() throws RemoteException, InvalidSsmQueryException;

}
