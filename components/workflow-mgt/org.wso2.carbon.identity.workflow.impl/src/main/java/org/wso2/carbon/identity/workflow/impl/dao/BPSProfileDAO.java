/*
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.workflow.impl.dao;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.core.util.CryptoUtil;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.workflow.impl.WorkflowImplException;
import org.wso2.carbon.identity.workflow.impl.bean.BPSProfile;
import org.wso2.carbon.identity.workflow.mgt.util.SQLConstants;

import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class BPSProfileDAO {

    private static final String CIPHER_TRANSFORMATION_SYSTEM_PROPERTY = "org.wso2.CipherTransformation";
    private static Log log = LogFactory.getLog(BPSProfileDAO.class);

    /**
     * Add a new BPS profile
     *
     * @param bpsProfileDTO Details of profile to add
     * @param tenantId      ID of tenant domain
     * @throws WorkflowImplException
     */
    public void addProfile(BPSProfile bpsProfileDTO, int tenantId)
            throws WorkflowImplException {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        String query = SQLConstants.ADD_BPS_PROFILE_QUERY;
        String password = String.copyValueOf(bpsProfileDTO.getPassword());
        String profileName = bpsProfileDTO.getProfileName();
        String encryptedPassword;

        try {
            encryptedPassword = encryptPassword(password);
        } catch (CryptoException e) {
            throw new WorkflowImplException("Error while encrypting the passwords of BPS Profile: " + profileName, e);
        }

        try {
            prepStmt = connection.prepareStatement(query);
            prepStmt.setString(1, bpsProfileDTO.getProfileName());
            prepStmt.setString(2, bpsProfileDTO.getManagerHostURL());
            prepStmt.setString(3, bpsProfileDTO.getWorkerHostURL());
            prepStmt.setString(4, bpsProfileDTO.getUsername());
            prepStmt.setString(5, encryptedPassword);
            prepStmt.setInt(6, tenantId);
            prepStmt.executeUpdate();
            connection.commit();
        } catch (SQLException e) {
            throw new WorkflowImplException("Error when executing the sql query", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
    }


    /**
     * Update existing BPS Profile
     *
     * @param bpsProfile BPS profile object with new details
     * @param tenantId   ID of tenant domain
     * @throws WorkflowImplException
     */
    public void updateProfile(BPSProfile bpsProfile, int tenantId)
            throws WorkflowImplException {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        String query = SQLConstants.UPDATE_BPS_PROFILE_QUERY;
        String password = String.copyValueOf(bpsProfile.getPassword());
        String profileName = bpsProfile.getProfileName();
        String encryptedPassword;

        try {
            encryptedPassword = encryptPassword(password);
        } catch (CryptoException e) {
            throw new WorkflowImplException("Error while encrypting the passwords of BPS Profile: " + profileName, e);
        }

        try {
            prepStmt = connection.prepareStatement(query);
            prepStmt.setString(1, bpsProfile.getManagerHostURL());
            prepStmt.setString(2, bpsProfile.getWorkerHostURL());
            prepStmt.setString(3, bpsProfile.getUsername());
            prepStmt.setString(4, encryptedPassword);
            prepStmt.setInt(5, tenantId);
            prepStmt.setString(6, bpsProfile.getProfileName());

            prepStmt.executeUpdate();
            connection.commit();
        } catch (SQLException e) {
            throw new WorkflowImplException("Error when executing the sql query", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
    }

    /**
     * Retrieve details of a BPS profile
     *
     * @param profileName     Name of profile to retrieve
     * @param tenantId        Id of tenant domain
     * @param isWithPasswords Whether password to be retrieved or not
     * @return
     * @throws WorkflowImplException
     */
    public BPSProfile getBPSProfile(String profileName, int tenantId, boolean isWithPasswords) throws
                                                                                               WorkflowImplException {

        BPSProfile bpsProfileDTO = null;

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet rs;
        String query = SQLConstants.GET_BPS_PROFILE_FOR_TENANT_QUERY;
        String decryptedPassword;
        boolean migrationRequired = false;

        try {
            prepStmt = connection.prepareStatement(query);
            prepStmt.setString(1, profileName);
            prepStmt.setInt(2, tenantId);
            rs = prepStmt.executeQuery();

            if (rs.next()) {
                String managerHostName = rs.getString(SQLConstants.HOST_URL_MANAGER_COLUMN);
                String workerHostName = rs.getString(SQLConstants.HOST_URL_WORKER_COLUMN);
                String user = rs.getString(SQLConstants.USERNAME_COLUMN);

                bpsProfileDTO = new BPSProfile();
                bpsProfileDTO.setProfileName(profileName);
                bpsProfileDTO.setManagerHostURL(managerHostName);
                bpsProfileDTO.setWorkerHostURL(workerHostName);
                bpsProfileDTO.setUsername(user);

                if (isWithPasswords) {
                    String password = rs.getString(SQLConstants.PASSWORD_COLUMN);

                    try {
                        decryptedPassword = decryptPassword(password);

                    } catch (CryptoException | UnsupportedEncodingException e) {
                        throw new WorkflowImplException("Error while decrypting the password for BPEL Profile "
                                + profileName, e);
                    }
                    bpsProfileDTO.setPassword(decryptedPassword.toCharArray());
                    try {
                        if (isMigrationRequired(password)) {
                            migrationRequired = true;
                        }
                    } catch (CryptoException e) {
                        throw new WorkflowImplException("Error while validating migration requirement of the password "
                                + "for BPEL Profile " + profileName, e);
                    }
                }

            }
        } catch (SQLException e) {
            throw new WorkflowImplException("Error when executing the sql.", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }

        if (migrationRequired) {
            log.info("Migrating password encryption of BPS profile : " + bpsProfileDTO.getProfileName());
            //Update the profile, this will re-encrypt the password as self-contained ciphertext
            updateProfile(bpsProfileDTO, tenantId);

            // Retrieve the profile from the DB again, this is done to avoid infinite loop may cause by recalling
            // org.wso2.carbon.identity.workflow.impl.dao.BPSProfileDAO.getBPSProfile function
            connection = IdentityDatabaseUtil.getDBConnection();
            try {
                prepStmt = connection.prepareStatement(query);
                prepStmt.setString(1, profileName);
                prepStmt.setInt(2, tenantId);
                rs = prepStmt.executeQuery();

                if (rs.next()) {
                    String managerHostName = rs.getString(SQLConstants.HOST_URL_MANAGER_COLUMN);
                    String workerHostName = rs.getString(SQLConstants.HOST_URL_WORKER_COLUMN);
                    String user = rs.getString(SQLConstants.USERNAME_COLUMN);
                    bpsProfileDTO = new BPSProfile();
                    bpsProfileDTO.setProfileName(profileName);
                    bpsProfileDTO.setManagerHostURL(managerHostName);
                    bpsProfileDTO.setWorkerHostURL(workerHostName);
                    bpsProfileDTO.setUsername(user);

                    String password = rs.getString(SQLConstants.PASSWORD_COLUMN);
                    try {
                        bpsProfileDTO.setPassword(decryptPassword(password).toCharArray());
                    } catch (CryptoException | UnsupportedEncodingException e) {
                        throw new WorkflowImplException(
                                "Error while decrypting the password for BPEL Profile " + profileName, e);
                    }
                }
            } catch (SQLException e) {
                throw new WorkflowImplException("Error when executing the sql " + query, e);
            } finally {
                IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
            }
        }

        return bpsProfileDTO;
    }


    /**
     * Retrieve list of existing BPS profiles
     *
     * @param tenantId  Id of tenant domain to retrieve BPS profiles
     * @return
     * @throws WorkflowImplException
     */
    public List<BPSProfile> listBPSProfiles(int tenantId) throws WorkflowImplException {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet rs;
        List<BPSProfile> profiles = new ArrayList<>();
        String query = SQLConstants.LIST_BPS_PROFILES_QUERY;
        String decryptPassword;
        CryptoUtil cryptoUtil = CryptoUtil.getDefaultCryptoUtil();

        // List of BPS profiles that required for for encryption migration.
        List<BPSProfile> encryptionMigrationProfiles = null;
        try {
            Object classCheckResult = null;
            //Checks if IS has BPS features installed with it
            try {
                classCheckResult = Class.forName("org.wso2.carbon.humantask.deployer.HumanTaskDeployer");
            } catch (ClassNotFoundException e) {
                //If BPS features are not installed, it will throw a ClassNotFoundException, no actionto be executed
                // here
            }
            prepStmt = connection.prepareStatement(query);
            prepStmt.setInt(1, tenantId);
            rs = prepStmt.executeQuery();
            while (rs.next()) {
                String name = rs.getString(SQLConstants.PROFILE_NAME_COLUMN);
                if (classCheckResult == null && name.equals("embeded_bps")) {
                    continue;
                }
                String managerHostName = rs.getString(SQLConstants.HOST_URL_MANAGER_COLUMN);
                String workerHostName = rs.getString(SQLConstants.HOST_URL_WORKER_COLUMN);
                String user = rs.getString(SQLConstants.USERNAME_COLUMN);
                String password = rs.getString(SQLConstants.PASSWORD_COLUMN);
                try {
                    byte[] decryptedPasswordBytes = cryptoUtil.base64DecodeAndDecrypt(password);
                    decryptPassword = new String(decryptedPasswordBytes, "UTF-8");
                } catch (CryptoException | UnsupportedEncodingException e) {
                    throw new WorkflowImplException("Error while decrypting the password for BPEL Profile " +
                            name, e);
                }
                BPSProfile profileBean = new BPSProfile();
                profileBean.setManagerHostURL(managerHostName);
                profileBean.setWorkerHostURL(workerHostName);
                profileBean.setProfileName(name);
                profileBean.setUsername(user);
                profileBean.setPassword(decryptPassword.toCharArray());
                try {
                    // Encrypted data migration for OAEP Fix : If custom transformation used, and current encrypted
                    // password is not self-contained cipher, so migrate password encryption to self-contained ciphertext.
                    if (isMigrationRequired(password)) {
                        if (encryptionMigrationProfiles == null) {
                            encryptionMigrationProfiles = new ArrayList<>();
                        }
                        // Add the profile to a different list since it's required to migrate.
                        encryptionMigrationProfiles.add(profileBean);
                    } else {
                        profiles.add(profileBean);
                    }
                } catch (CryptoException e) {
                    throw new WorkflowImplException("Error while migrating encryption of the password for BPEL Profile "
                            + name, e);
                }
            }
        } catch (SQLException e) {
            throw new WorkflowImplException("Error when executing the sql.", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }

        // Encrypted data migration for OAEP Fix.
        if (encryptionMigrationProfiles != null) {
            for (BPSProfile encryptionMigrationProfile : encryptionMigrationProfiles) {
                //Add the profile back to return list after migration
                profiles.add(performEncryptionMigration(encryptionMigrationProfile, tenantId));
            }
        }
        return profiles;
    }


    /**
     * Delete a BPS profile
     *
     * @param profileName Name of the profile to retrieve
     * @throws WorkflowImplException
     */
    public void removeBPSProfile(String profileName) throws WorkflowImplException {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        String query = SQLConstants.DELETE_BPS_PROFILES_QUERY;
        try {
            prepStmt = connection.prepareStatement(query);
            prepStmt.setString(1, profileName);
            prepStmt.executeUpdate();
            connection.commit();
        } catch (SQLException e) {
            throw new WorkflowImplException("Error when executing the sql.", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
    }

    private String encryptPassword(String passwordValue) throws CryptoException {

        CryptoUtil cryptoUtil = CryptoUtil.getDefaultCryptoUtil();
        return cryptoUtil.encryptAndBase64Encode(passwordValue.getBytes(Charset.forName("UTF-8")));
    }

    private String decryptPassword(String passwordValue) throws UnsupportedEncodingException, CryptoException {

        CryptoUtil cryptoUtil = CryptoUtil.getDefaultCryptoUtil();
        byte[] decryptedPasswordBytes = cryptoUtil.base64DecodeAndDecrypt(passwordValue);
        return new String(decryptedPasswordBytes, "UTF-8");

    }


    /**
     * Encrypted data migration for OAEP Fix : If custom transformation used, and current encrypted password is not
     * self-contained cipher, so migrate password encryption to self-contained ciphertext. This function validates
     * whether it is required to migrate or not
     *
     * @param ciphertext cipher text
     * @return true if required to migrate, false otherwise
     * @throws CryptoException
     */
    private boolean isMigrationRequired(String ciphertext) throws CryptoException {

        return System.getProperty(CIPHER_TRANSFORMATION_SYSTEM_PROPERTY) != null &&
                !(CryptoUtil.getDefaultCryptoUtil().base64DecodeAndIsSelfContainedCipherText(ciphertext));
    }


    private BPSProfile performEncryptionMigration(BPSProfile bpsProfile, int tenantId) throws WorkflowImplException {
        return getBPSProfile(bpsProfile.getProfileName(), tenantId, true);
    }

}
