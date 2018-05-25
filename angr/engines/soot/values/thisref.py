
from .base import SimSootValue
from .local import SimSootValue_Local

class SimSootValue_ThisRef(SimSootValue):

    __slots__ = [ 'id', 'type', 'heap_alloc_id' ]

    def __init__(self, heap_alloc_id, type_):
        self.id = self._create_unique_id(heap_alloc_id, type_)
        self.heap_alloc_id = heap_alloc_id
        self.type = type_

    @staticmethod
    def _create_unique_id(heap_alloc_id, class_name):
        return "%s.%s.this" % (heap_alloc_id, class_name)

    @classmethod
    def from_sootvalue(cls, soot_value, state):
        local = SimSootValue_Local("%s.this" % soot_value.type, soot_value.type)
        return state.memory.load(local)

    def __repr__(self):
        return self.id