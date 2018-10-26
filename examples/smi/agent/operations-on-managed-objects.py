"""
Agent operations on MIB
+++++++++++++++++++++++

This script explains how SNMP Agent application manipulates
its MIB possibly triggered by SNMP Manager's commands.

"""#
# SNMP agent backend e.g. Agent access to Managed Objects
from pysnmp.smi import builder, instrum, exval
from pysnmp import debug

#debug.setLogger(debug.Debug('all'))

print('Loading MIB modules...'),
mibBuilder = builder.MibBuilder().loadModules(
    'SNMPv2-MIB', 'SNMP-FRAMEWORK-MIB', 'SNMP-COMMUNITY-MIB'
)
print('done')

print('Building MIB tree...'),
mibInstrum = instrum.MibInstrumController(mibBuilder)
print('done')

print('Building table entry index from human-friendly representation...'),
snmpCommunityEntry, = mibBuilder.importSymbols(
    'SNMP-COMMUNITY-MIB', 'snmpCommunityEntry'
)
instanceId = snmpCommunityEntry.getInstIdFromIndices('my-router')
print('done')


def cbFun(varBinds, **context):
    for oid, val in varBinds:
        print('%s = %s' % ('.'.join([str(x) for x in oid]), not val.isValue and 'N/A' or val.prettyPrint()))


print('Create/update SNMP-COMMUNITY-MIB::snmpCommunityEntry table row: ')
mibInstrum.writeVars(
    (snmpCommunityEntry.name + (2,) + instanceId, 'mycomm'),
    (snmpCommunityEntry.name + (3,) + instanceId, 'mynmsname'),
    (snmpCommunityEntry.name + (7,) + instanceId, 'volatile'),
    cbFun=cbFun
)
print('done')


def cbFun(varBinds, **context):
    for oid, val in varBinds:
        if exval.endOfMib.isSameTypeWith(val):
            context['app']['stop'] = True
        print('%s = %s' % ('.'.join([str(x) for x in oid]), not val.isValue and 'N/A' or val.prettyPrint()))

    context['app']['varBinds'] = varBinds


app_context = {
    'varBinds': [((1, 3, 6), None)],
    'stop': False
}

print('Read whole MIB (table walk)')
while not app_context['stop']:
    mibInstrum.readNextVars(*app_context['varBinds'], cbFun=cbFun, app=app_context)
print('done')

print('Unloading MIB modules...'),
mibBuilder.unloadModules()
print('done')
