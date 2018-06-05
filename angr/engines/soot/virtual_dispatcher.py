
from archinfo.arch_soot import SootMethodDescriptor
from angr.engines.soot.expressions import translate_expr


# TODO implement properly
# this will need the expression, the class hierarchy, and the position of the instruction (for invoke-super)
# this will also need the current state to try to figure out the dynamic type


def resolve_method(state, expr):
    base_this = translate_expr(expr.base, state)
    # Sometimes "this" is None for example when we use a method from a library
    # (i. e. System.out.Println)
    #
    # In this case we just keep the type retrieved statically by soot
    if base_this.expr is None:
        return SootMethodDescriptor(expr.class_name, expr.method_name, expr.method_params)
    return SootMethodDescriptor(base_this.expr.type, expr.method_name, expr.method_params)
