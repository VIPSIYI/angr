
import claripy

from archinfo.arch_soot import SootAddressTerminator

from ..sim_state import SimState
from .simos import SimOS
from ..engines.soot.values.arrayref import SimSootValue_ArrayRef
from ..engines.soot.values.local import SimSootValue_Local
from archinfo.arch_soot import SootAddressDescriptor, SootMethodDescriptor


class SimJavaVM(SimOS):

    def __init__(self, *args, **kwargs):
        super(SimJavaVM, self).__init__(*args, name='JavaVM', **kwargs)

    @staticmethod
    def get_default_value_by_type(type_):
        """
        Java specify defaults values for initialized field based on the field type.
        This method returns these default values given a type.
        (https://blog.ajduke.in/2012/03/25/variable-initialization-and-default-values)

        TODO: ask what to do for symbolic value and under constraint symbolic execution
        :param type_: string represent the type name
        :return: Default values specified for the type
        """
        if type_ == "int":
            return claripy.BVV(0, 32)
        elif type_ == "boolean":
            return claripy.BoolV(False)
        else:
            return None

    def state_blank(self, addr=None, initial_prefix=None, stack_size=None, **kwargs):
        if kwargs.get('mode', None) is None:
            kwargs['mode'] = self.project._default_analysis_mode
        if kwargs.get('arch', None) is None:
            kwargs['arch'] = self.arch
        if kwargs.get('os_name', None) is None:
            kwargs['os_name'] = self.name

        state = SimState(self.project, **kwargs)

        if addr is None: addr = self.project.entry
        state.regs._ip = addr
        state.regs._ip_binary = self.project.loader.main_object  # FIXME: what if the java binary is not the main object?
        state.regs._invoke_return_target = None
        state.regs._invoke_return_variable = None

        # Push the stack frame for the next function we are going to execute
        state.memory.push_stack_frame()
        new_frame = state.callstack.copy()
        new_frame.ret_addr = SootAddressTerminator()
        state.callstack.push(new_frame)

        return state

    def state_entry(self, args=None, env=None, argc=None, **kwargs):
        state = self.state_blank(**kwargs)

        # Push the array of command line arguments on the stack frame
        if args is None:
            args = [state.se.StringS("cmd_arg", 1000) for _ in range(100)]
        # if the user provides only one arguments create a list
        elif not isinstance(args, list):
            args = [args]

        # Since command line arguments are stored into arrays in Java
        # and arrays are stored on the heap we need to allocate the array on the heap\
        # and return the reference
        size_ = len(args)
        type_ = "String[]"
        heap_alloc_id = state.memory.get_new_uuid()
        for idx, elem in enumerate(args):
            ref = SimSootValue_ArrayRef(heap_alloc_id, idx, type_, size_)
            state.memory.store(ref, elem)
        base_ref = SimSootValue_ArrayRef(heap_alloc_id, 0, type_, size_)
        local = SimSootValue_Local("param_0", type_)
        state.memory.store(local, base_ref)

        # Sometimes classes has a special method called "<clinit> that initialize part
        # of the class such as static field with default value etc.
        # This method would never be executed in a normal exploration so at class
        # loading time (loading of the main class in this case) we force the symbolic execution
        # of the method <clinit> and we update the state accordingly.
        manifest = state.project.loader.main_bin.get_manifest()
        main_cls = state.project.loader.main_bin.get_class(manifest["Main-Class"])
        for method in main_cls.methods:
            if method.name == "<clinit>":
                entry_state = state.copy()
                simgr = state.project.factory.simgr(entry_state)
                simgr.active[0].ip = SootAddressDescriptor(SootMethodDescriptor.from_method(method), 0, 0)
                simgr.run()
                # if we reach the end of the method the correct state is the deadended state
                if simgr.deadended:
                    # The only thing that can change in the <clinit> methods are static fields so
                    # it can only change the vm_static_table and the heap.
                    # We need to fix the entry state memory with the new memory state.
                    state.memory.vm_static_table = simgr.deadended[0].memory.vm_static_table.copy()
                    state.memory.heap = simgr.deadended[0].memory.heap.copy()
                break

        return state


