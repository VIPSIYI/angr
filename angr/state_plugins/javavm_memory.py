
import binascii
import os

from ..engines.soot.values import SimSootValue_Local, SimSootValue_ArrayRef, SimSootValue_ParamRef, \
                                  SimSootValue_StaticFieldRef, SimSootValue_ThisRef, SimSootValue_InstanceFieldRef

from ..storage.memory import SimMemory
from .keyvalue_memory import SimKeyValueMemory

MAX_ARRAY_SIZE = 1000


class SimJavaVmMemory(SimMemory):
    def __init__(self, memory_id="mem", stack=None, heap=None, vm_static_table=None):
        super(SimJavaVmMemory, self).__init__()

        self.id = memory_id

        self._stack = [ ] if stack is None else stack
        self.heap = SimKeyValueMemory("mem") if heap is None else heap
        self.vm_static_table = SimKeyValueMemory("mem") if vm_static_table is None else vm_static_table

        # Heap helper
        # TODO: ask someone how we want to manage this
        # TODO: Manage out of memory allocation
        # self._heap_allocation_id = 0
        self.max_array_size = MAX_ARRAY_SIZE

    def get_new_uuid(self):
        # self._heap_allocation_id += 1
        # return str(self._heap_allocation_id)
        return binascii.hexlify(os.urandom(4))

    def store(self, addr, data, size=None, condition=None, add_constraints=None, endness=None, action=None,
              inspect=True, priv=None, disable_actions=False, frame=0):

        if type(addr) is SimSootValue_Local:
            cstack = self._stack[-1+(-1*frame)]
            # A local variable
            # TODO: Implement the stacked stack frames model
            cstack.store(addr.id, data, type_=addr.type)
        elif type(addr) is SimSootValue_ArrayRef:
            self.heap.store(addr.id, data, type_=addr.type)
        elif type(addr) is SimSootValue_StaticFieldRef:
            self.vm_static_table.store(addr.id, data, type_=addr.type)
        elif type(addr) is SimSootValue_InstanceFieldRef:
            self.heap.store(addr.id, data, type_=addr.type)
        else:
            import ipdb; ipdb.set_trace()

    def load(self, addr, size=None, condition=None, fallback=None, add_constraints=None, action=None, endness=None,
             inspect=True, disable_actions=False, ret_on_segv=False, none_if_missing=False, frame=0):

        if type(addr) is SimSootValue_Local:
            cstack = self._stack[-1+(-1*frame)]
            # Load a local variable
            # TODO: Implement the stacked stack frames model
            return cstack.load(addr.id, none_if_missing=True)
        elif type(addr) is SimSootValue_ArrayRef:
            return self.heap.load(addr.id, none_if_missing=True)
        elif type(addr) is SimSootValue_ParamRef:
            cstack = self._stack[-1+(-1*frame)]
            # Load a local variable
            # TODO: Implement the stacked stack frames model
            return cstack.load(addr.id, none_if_missing=True)
        elif type(addr) is SimSootValue_StaticFieldRef:
            return self.vm_static_table.load(addr.id, none_if_missing=True)
        elif type(addr) is SimSootValue_InstanceFieldRef:
            return self.heap.load(addr.id, none_if_missing=True)
        else:
            import ipdb; ipdb.set_trace()

    def copy(self):
        return SimJavaVmMemory(
            memory_id=self.id,
            stack=[stack_frame.copy() for stack_frame in self._stack],
            heap=self.heap.copy(),
            vm_static_table=self.vm_static_table.copy()
        )

    def push_stack_frame(self):
        self._stack.append(SimKeyValueMemory("mem"))

    def pop_stack_frame(self):
        self._stack = self._stack[:-1]

    @property
    def stack(self):
        return self._stack[-1]
