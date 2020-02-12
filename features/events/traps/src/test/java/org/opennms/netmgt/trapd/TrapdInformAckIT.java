/*******************************************************************************
 * This file is part of OpenNMS(R).
 *
 * Copyright (C) 2020 The OpenNMS Group, Inc.
 * OpenNMS(R) is Copyright (C) 1999-2020 The OpenNMS Group, Inc.
 *
 * OpenNMS(R) is a registered trademark of The OpenNMS Group, Inc.
 *
 * OpenNMS(R) is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version.
 *
 * OpenNMS(R) is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with OpenNMS(R).  If not, see:
 *      http://www.gnu.org/licenses/
 *
 * For more information contact:
 *     OpenNMS(R) Licensing <license@opennms.org>
 *     http://www.opennms.org/
 *     http://www.opennms.com/
 *******************************************************************************/

package org.opennms.netmgt.trapd;

import static com.jayway.awaitility.Awaitility.await;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opennms.core.test.OpenNMSJUnit4ClassRunner;
import org.opennms.core.test.db.annotations.JUnitTemporaryDatabase;
import org.opennms.core.utils.InetAddressUtils;
import org.opennms.netmgt.config.TrapdConfigFactory;
import org.opennms.netmgt.config.trapd.Snmpv3User;
import org.opennms.netmgt.dao.mock.MockEventIpcManager;
import org.opennms.netmgt.snmp.SnmpAgentConfig;
import org.opennms.netmgt.snmp.SnmpObjId;
import org.opennms.netmgt.snmp.SnmpValue;
import org.opennms.netmgt.snmp.snmp4j.Snmp4JAgentConfig;
import org.opennms.netmgt.snmp.snmp4j.Snmp4JStrategy;
import org.opennms.netmgt.snmp.snmp4j.Snmp4JValue;
import org.opennms.test.JUnitConfigurationEnvironment;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.snmp4j.PDU;
import org.snmp4j.ScopedPDU;
import org.snmp4j.Snmp;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.event.ResponseListener;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.Variable;
import org.snmp4j.smi.VariableBinding;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;

@RunWith(OpenNMSJUnit4ClassRunner.class)
@ContextConfiguration(locations={
        "classpath:/META-INF/opennms/applicationContext-soa.xml",
        "classpath:/META-INF/opennms/applicationContext-dao.xml",
        "classpath*:/META-INF/opennms/component-dao.xml",
        "classpath:/META-INF/opennms/mockEventIpcManager.xml",
        "classpath:/META-INF/opennms/applicationContext-commonConfigs.xml",
        "classpath:/META-INF/opennms/applicationContext-minimal-conf.xml",
        "classpath:/META-INF/opennms/applicationContext-daemon.xml",
        "classpath:/META-INF/opennms/applicationContext-trapDaemon.xml",
        // Overrides the port that Trapd binds to and sets newSuspectOnTrap to 'true'
        "classpath:/org/opennms/netmgt/trapd/applicationContext-trapDaemonTest.xml"
})
@JUnitConfigurationEnvironment
@JUnitTemporaryDatabase
public class TrapdInformAckIT {

    private static final Logger LOG = LoggerFactory.getLogger(TrapdInformAckIT.class);
    @Autowired
    private TrapdConfigFactory m_trapdConfig;

    @Autowired
    Trapd m_trapd;

    @Autowired
    MockEventIpcManager m_mockEventIpcManager;

    private final InetAddress localAddr = InetAddressUtils.getLocalHostAddress();
    private final String localhost = InetAddressUtils.toIpAddrString(localAddr);

    @Before
    public void setUp() {
        m_mockEventIpcManager.setSynchronous(true);
        m_trapd.onStart();
    }

    @After
    public void tearDown() {
        m_trapd.onStop();
        m_mockEventIpcManager.getEventAnticipator().verifyAnticipated(3000, 0, 0, 0, 0);
    }

    @Test
    public void testAckforInform() throws Exception {
        // Retrieve a v3 user from the configuration
        SecurityLevel securityLevel = SecurityLevel.noAuthNoPriv;
        final Snmpv3User v3User = m_trapdConfig.getConfig().getSnmpv3UserCollection().stream()
                .filter(u -> Objects.equals(securityLevel.getSnmpValue(), u.getSecurityLevel()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("No existing SNMPv3 user configured with security level: " + securityLevel));

        ScopedPDU scopedPDU = new ScopedPDU();
        scopedPDU.setType(PDU.INFORM);
        OctetString contextName = new OctetString();
        scopedPDU.setContextName(contextName);
        OctetString contextEngineID = new OctetString();
        scopedPDU.setContextEngineID(contextEngineID);
        final Snmp4JStrategy strategy = new Snmp4JStrategy();
        addVarBind(SnmpObjId.get(".1.3.6.1.2.1.1.3.0"), strategy.getValueFactory().getTimeTicks(0), scopedPDU);

        SnmpAgentConfig config = buildAgentConfig(localhost,
                m_trapdConfig.getSnmpTrapPort(),
                5000,
                3,
                v3User.getSecurityLevel(),
                v3User.getSecurityName(),
                v3User.getAuthPassphrase(),
                v3User.getAuthProtocol(),
                v3User.getPrivacyPassphrase(),
                v3User.getPrivacyProtocol(), scopedPDU);
        Snmp4JAgentConfig agentConfig = new Snmp4JAgentConfig(config);
        Snmp session = agentConfig.createSnmpSession();
        Snmp4JStrategy.trackSession(session);
        try {
            session.listen();
        } catch (final Exception e) {
            closeQuietly(session);
            return;
        }
        AtomicInteger responseEventCount = new AtomicInteger(0);
        Assert.assertEquals(responseEventCount.get(), 0);
        session.send(scopedPDU, agentConfig.getTarget(), null, new ResponseListener() {
            @Override
            public void onResponse(final ResponseEvent responseEvent) {
                Assert.assertTrue(responseEvent.getRequest().isConfirmedPdu());
                ScopedPDU requestPDU = (ScopedPDU) responseEvent.getRequest();
                Assert.assertEquals(new OctetString(agentConfig.getLocalEngineId()), requestPDU.getContextEngineID());
                responseEventCount.incrementAndGet();
            }
        });

        await().atMost(10, SECONDS).until(responseEventCount::get, greaterThanOrEqualTo(1));
        m_trapd.onStop();
        m_trapd.onStart();
        closeQuietly(session);

    }

    private static void closeQuietly(Snmp session) {
        if (session == null) {
            return;
        }

        try {
            session.close();
        } catch (IOException e) {
            LOG.error("error closing SNMP connection", e);
        } finally {
            Snmp4JStrategy.reapSession(session);
        }
    }

    private SnmpAgentConfig buildAgentConfig(String address, int port, int timeout, int retries, int securityLevel,
                                               String securityName, String authPassPhrase, String authProtocol,
                                               String privPassPhrase, String privProtocol, PDU pdu) throws UnknownHostException, Exception {

        SnmpAgentConfig config = new SnmpAgentConfig();
        config.setAddress(InetAddress.getByName(address));
        config.setPort(port);
        config.setVersion(SnmpAgentConfig.VERSION3);
        config.setSecurityLevel(securityLevel);
        config.setSecurityName(securityName);
        config.setAuthPassPhrase(authPassPhrase);
        config.setAuthProtocol(authProtocol);
        config.setPrivPassPhrase(privPassPhrase);
        config.setPrivProtocol(privProtocol);
        config.setTimeout(timeout);
        config.setRetries(retries);
        return config;

    }

    public void addVarBind(SnmpObjId name, SnmpValue value, PDU pdu) {
        OID oid = new OID(name.getIds());
        Variable val = ((Snmp4JValue) value).getVariable();
        pdu.add(new VariableBinding(oid, val));
    }


}
