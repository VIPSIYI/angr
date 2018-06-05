
from ..virtual_dispatcher import resolve_method
from .base import SimSootStmt
import logging


l = logging.getLogger('angr.engines.soot.statements.invoke')

class SimSootStmt_Invoke(SimSootStmt):
    def __init__(self, stmt, state):
        super(SimSootStmt_Invoke, self).__init__(stmt, state)

    def _execute(self):
        self._translate_expr(self.stmt.invoke_expr)


