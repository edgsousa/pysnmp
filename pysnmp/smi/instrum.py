#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2018, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
import sys
import traceback
import functools
from pysnmp import nextid
from pysnmp.proto import rfc1905
from pysnmp.smi import error
from pysnmp import debug

__all__ = ['AbstractMibInstrumController', 'MibInstrumController']


class AbstractMibInstrumController(object):
    def readVars(self, *varBinds, **context):
        raise error.NoSuchInstanceError(idx=0)

    def readNextVars(self, *varBinds, **context):
        raise error.EndOfMibViewError(idx=0)

    def writeVars(self, *varBinds, **context):
        raise error.NoSuchObjectError(idx=0)


class MibInstrumController(AbstractMibInstrumController):
    STATUS_OK = 'ok'
    STATUS_ERROR = 'err'
    
    STATE_START = 'start'
    STATE_STOP = 'stop'
    STATE_ANY = '*'
    # These states are actually methods of the MIB objects
    STATE_READ_TEST = 'readTest'
    STATE_READ_GET = 'readGet'
    STATE_READ_TEST_NEXT = 'readTestNext'
    STATE_READ_GET_NEXT = 'readGetNext'
    STATE_WRITE_TEST = 'writeTest'
    STATE_WRITE_COMMIT = 'writeCommit'
    STATE_WRITE_CLEANUP = 'writeCleanup'
    STATE_WRITE_UNDO = 'writeUndo'

    fsmReadVar = {
        # ( state, status ) -> newState
        (STATE_START, STATUS_OK): STATE_READ_TEST,
        (STATE_READ_TEST, STATUS_OK): STATE_READ_GET,
        (STATE_READ_GET, STATUS_OK): STATE_STOP,
        (STATE_ANY, STATUS_ERROR): STATE_STOP
    }
    fsmReadNextVar = {
        # ( state, status ) -> newState
        (STATE_START, STATUS_OK): STATE_READ_TEST_NEXT,
        (STATE_READ_TEST_NEXT, STATUS_OK): STATE_READ_GET_NEXT,
        (STATE_READ_GET_NEXT, STATUS_OK): STATE_STOP,
        (STATE_ANY, STATUS_ERROR): STATE_STOP
    }
    fsmWriteVar = {
        # ( state, status ) -> newState
        (STATE_START, STATUS_OK): STATE_WRITE_TEST,
        (STATE_WRITE_TEST, STATUS_OK): STATE_WRITE_COMMIT,
        (STATE_WRITE_COMMIT, STATUS_OK): STATE_WRITE_CLEANUP,
        (STATE_WRITE_CLEANUP, STATUS_OK): STATE_READ_TEST,
        # Do read after successful write
        (STATE_READ_TEST, STATUS_OK): STATE_READ_GET,
        (STATE_READ_GET, STATUS_OK): STATE_STOP,
        # Error handling
        (STATE_WRITE_TEST, STATUS_ERROR): STATE_WRITE_CLEANUP,
        (STATE_WRITE_COMMIT, STATUS_ERROR): STATE_WRITE_UNDO,
        (STATE_WRITE_UNDO, STATUS_OK): STATE_READ_TEST,
        # Ignore read errors (removed columns)
        (STATE_READ_TEST, STATUS_ERROR): STATE_STOP,
        (STATE_READ_GET, STATUS_ERROR): STATE_STOP,
        (STATE_ANY, STATUS_ERROR): STATE_STOP
    }

    FSM_CONTEXT = '_fsmContext'

    FSM_SESSION_ID = nextid.Integer(0xffffffff)

    def __init__(self, mibBuilder):
        self.mibBuilder = mibBuilder
        self.lastBuildId = -1
        self.lastBuildSyms = {}

    def getMibBuilder(self):
        return self.mibBuilder

    # MIB indexing

    def __indexMib(self):
        # Build a tree from MIB objects found at currently loaded modules
        if self.lastBuildId == self.mibBuilder.lastBuildId:
            return

        (MibScalarInstance, MibScalar, MibTableColumn, MibTableRow,
         MibTable) = self.mibBuilder.importSymbols(
            'SNMPv2-SMI', 'MibScalarInstance', 'MibScalar',
            'MibTableColumn', 'MibTableRow', 'MibTable'
        )

        mibTree, = self.mibBuilder.importSymbols('SNMPv2-SMI', 'iso')

        #
        # Management Instrumentation gets organized as follows:
        #
        # MibTree
        #   |
        #   +----MibScalar
        #   |        |
        #   |        +-----MibScalarInstance
        #   |
        #   +----MibTable
        #   |
        #   +----MibTableRow
        #          |
        #          +-------MibTableColumn
        #                        |
        #                        +------MibScalarInstance(s)
        #
        # Mind you, only Managed Objects get indexed here, various MIB defs and
        # constants can't be SNMP managed so we drop them.
        #
        scalars = {}
        instances = {}
        tables = {}
        rows = {}
        cols = {}

        # Sort by module name to give user a chance to slip-in
        # custom MIB modules (that would be sorted out first)
        mibSymbols = list(self.mibBuilder.mibSymbols.items())
        mibSymbols.sort(key=lambda x: x[0], reverse=True)

        for modName, mibMod in mibSymbols:
            for symObj in mibMod.values():
                if isinstance(symObj, MibTable):
                    tables[symObj.name] = symObj
                elif isinstance(symObj, MibTableRow):
                    rows[symObj.name] = symObj
                elif isinstance(symObj, MibTableColumn):
                    cols[symObj.name] = symObj
                elif isinstance(symObj, MibScalarInstance):
                    instances[symObj.name] = symObj
                elif isinstance(symObj, MibScalar):
                    scalars[symObj.name] = symObj

        # Detach items from each other
        for symName, parentName in self.lastBuildSyms.items():
            if parentName in scalars:
                scalars[parentName].unregisterSubtrees(symName)
            elif parentName in cols:
                cols[parentName].unregisterSubtrees(symName)
            elif parentName in rows:
                rows[parentName].unregisterSubtrees(symName)
            else:
                mibTree.unregisterSubtrees(symName)

        lastBuildSyms = {}

        # Attach Managed Objects Instances to Managed Objects
        for inst in instances.values():
            if inst.typeName in scalars:
                scalars[inst.typeName].registerSubtrees(inst)
            elif inst.typeName in cols:
                cols[inst.typeName].registerSubtrees(inst)
            else:
                raise error.SmiError(
                    'Orphan MIB scalar instance %r at %r' % (inst, self)
                )
            lastBuildSyms[inst.name] = inst.typeName

        # Attach Table Columns to Table Rows
        for col in cols.values():
            rowName = col.name[:-1]  # XXX
            if rowName in rows:
                rows[rowName].registerSubtrees(col)
            else:
                raise error.SmiError(
                    'Orphan MIB table column %r at %r' % (col, self)
                )
            lastBuildSyms[col.name] = rowName

        # Attach Table Rows to MIB tree
        for row in rows.values():
            mibTree.registerSubtrees(row)
            lastBuildSyms[row.name] = mibTree.name

        # Attach Tables to MIB tree
        for table in tables.values():
            mibTree.registerSubtrees(table)
            lastBuildSyms[table.name] = mibTree.name

        # Attach Scalars to MIB tree
        for scalar in scalars.values():
            mibTree.registerSubtrees(scalar)
            lastBuildSyms[scalar.name] = mibTree.name

        self.lastBuildSyms = lastBuildSyms

        self.lastBuildId = self.mibBuilder.lastBuildId

        debug.logger & debug.flagIns and debug.logger('__indexMib: rebuilt')

    # MIB instrumentation

    def flipFlopFsm(self, fsmTable, *varBinds, **context):

        count = [0]

        cbFun = context['cbFun']

        def _cbFun(varBind, **context):
            idx = context.pop('idx', None)

            _varBinds = context['varBinds']

            name, value = varBind

            # Watch for possible exception tuple
            if isinstance(value, tuple):

                exc_type, exc_value, traceback = value

                if isinstance(exc_value, error.NoSuchObjectError):
                    value = rfc1905.noSuchObject

                elif isinstance(exc_value, error.NoSuchInstanceError):
                    value = rfc1905.noSuchOInstance

                elif isinstance(exc_value, error.EndOfMibViewError):
                    value = rfc1905.endOfMibView

                elif isinstance(exc_value, Exception):
                    raise value

            _varBinds[idx] = name, value

            if idx is None:
                cbFun(_varBinds, **context)
                return

            count[0] += 1

            debug.logger & debug.flagIns and debug.logger(
                '_cbFun: var-bind %d, processed %d, expected %d' % (
                idx, count[0], len(varBinds)))

            if count[0] < len(varBinds):
                return

            debug.logger & debug.flagIns and debug.logger(
                '_cbFun: finished, output var-binds %r' % (_varBinds,))

            self.flipFlopFsm(fsmTable, *varBinds, **dict(context, cbFun=cbFun))

        debug.logger & debug.flagIns and debug.logger('flipFlopFsm: input var-binds %r' % (varBinds,))

        mibTree, = self.mibBuilder.importSymbols('SNMPv2-SMI', 'iso')

        try:
            state = context['state']
            status = context['status']
            _varBinds = context['varBinds']

        except KeyError:
            state, status = self.STATE_START, self.STATUS_OK
            _varBinds = list(varBinds)

            self.__indexMib()

        debug.logger & debug.flagIns and debug.logger(
            'flipFlopFsm: current state %s, status %s' % (state, status))

        try:
            newState = fsmTable[(state, status)]

        except KeyError:
            try:
                newState = fsmTable[(self.STATE_ANY, status)]

            except KeyError:
                raise error.SmiError('Unresolved FSM state %s, %s' % (state, status))

        debug.logger & debug.flagIns and debug.logger(
            'flipFlopFsm: state %s status %s -> new state %s' % (state, status, newState))

        state = newState

        if state == self.STATE_STOP:
            context.pop(self.FSM_CONTEXT, None)
            context.pop('state', None)
            context.pop('status', None)
            context.pop('varBinds', None)
            context.pop('oName', None)
            if cbFun:
                cbFun(_varBinds, **context)
            return

        # the case of no var-binds
        if cbFun and not varBinds:
            _cbFun(None, **context)
            return

        mgmtFun = getattr(mibTree, state, None)
        if not mgmtFun:
            raise error.SmiError(
                'Unsupported state handler %s at %s' % (state, self)
            )

        for idx, varBind in enumerate(varBinds):

            try:
                mgmtFun(varBind, idx=idx, **dict(context, cbFun=_cbFun, state=state, status=status, varBinds=_varBinds, oName=None))

            except error.SmiError:
                exc = sys.exc_info()

                debug.logger & debug.flagIns and debug.logger(
                    'flipFlopFsm: fun %s exception %s for %r with traceback: %s' % (
                        mgmtFun, exc[0], varBind, traceback.format_exception(*exc)))

                varBind = varBind[0], exc

                _cbFun(varBind, idx=idx, **dict(context, status=self.STATUS_ERROR))

                return

            else:
                debug.logger & debug.flagIns and debug.logger(
                    'flipFlopFsm: func %s initiated for %r' % (mgmtFun, varBind))

    def readVars(self, *varBinds, **context):
        self.flipFlopFsm(self.fsmReadVar, *varBinds, **context)

    def readNextVars(self, *varBinds, **context):
        self.flipFlopFsm(self.fsmReadNextVar, *varBinds, **context)

    def writeVars(self, *varBinds, **context):
        self.flipFlopFsm(self.fsmWriteVar, *varBinds, **context)
